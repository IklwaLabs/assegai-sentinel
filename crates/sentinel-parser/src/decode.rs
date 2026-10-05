//! Layer 2-4 packet decoding.
//!
//! Design decision: Sentinel decodes L2-L4 with its own bounds-checked reader rather than
//! a general packet-parsing crate. Rationale:
//!
//! 1. The pipeline needs exact control over **truncation** (snaplen) and **IPv4
//!    fragmentation**, because the flow engine must not attribute a non-first fragment to
//!    a transport port. Generic slice APIs hide both behind "best effort" parsing.
//! 2. ARP must be decoded as a first-class citizen (it feeds device discovery and ARP
//!    spoof detection), which the available generic parsers do not expose through their
//!    unified slice type.
//! 3. Every read is bounds-checked and total: malformed input yields a typed error, never
//!    a panic and never a partially trusted length field.
//!
//! [`DecodeError`] is counted by the pipeline and never interrupts a capture session.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sentinel_common::error::{UserFacing, UserMessage};
use sentinel_common::net::MacAddr;
use sentinel_common::packet::{
    ArpMessage, ArpOpcode, EthernetFrame, IcmpHeader, IpHeader, Ipv4Header, Ipv6Header,
    NormalizedPacket, TcpFlags, TcpHeader, TransportHeader, TransportProtocol, UdpHeader, VlanTag,
    ethertype,
};

/// Ethernet II frame: 6 + 6 + 2 bytes.
const ETHERNET_HEADER_LEN: usize = 14;
/// IEEE 802.1Q tag inserted after the Ethernet header: 4 bytes.
const VLAN_TAG_LEN: usize = 4;
/// Minimum frame size that can carry a decodable Ethernet header.
const MIN_ETHERNET_FRAME_LEN: usize = ETHERNET_HEADER_LEN;
/// Length of the fixed part of an ARP message for Ethernet/IPv4.
const ARP_LEN: usize = 28;
/// Minimum TCP header length without options.
const MIN_TCP_LEN: usize = 20;
/// UDP header length.
const MIN_UDP_LEN: usize = 8;
/// Minimum ICMP header length (type, code, checksum).
const MIN_ICMP_LEN: usize = 4;
/// IPv4 header length without options.
const MIN_IPV4_LEN: usize = 20;
/// IPv6 fixed header length.
const IPV6_HEADER_LEN: usize = 40;

/// A decode failure. Malformed packets are counted, never fatal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// A layer ended before its header was complete.
    #[error("truncated {layer} header: need {needed} bytes, have {available}")]
    Truncated {
        /// Layer name, e.g. "IPv4".
        layer: &'static str,
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },

    /// An IP version field was neither 4 nor 6.
    #[error("unsupported IP version {0}")]
    UnsupportedIpVersion(u8),

    /// A header length field is smaller than its own minimum, or has an invalid shape.
    #[error("invalid {layer} length field: {value}")]
    InvalidLength {
        /// Layer name.
        layer: &'static str,
        /// Offending value.
        value: usize,
    },
}

impl UserFacing for DecodeError {
    fn user_message(&self) -> UserMessage {
        // Decode errors are counted and logged, never surfaced mid-session. This message
        // exists for diagnostics and support.
        UserMessage::new(
            "A captured packet could not be decoded",
            "Sentinel counted this packet and continued monitoring. Malformed or truncated frames are normal on busy networks.",
        )
        .with_details(self)
    }
}

/// Stateless packet decoder.
///
/// Holds no state between calls, so live capture and offline PCAP analysis execute exactly
/// the same code path.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketDecoder;

impl PacketDecoder {
    /// Creates a decoder.
    #[must_use]
    pub const fn new() -> Self {
        PacketDecoder
    }

    /// Decodes one captured frame into a [`NormalizedPacket`].
    ///
    /// `timestamp_us` is the capture time in microseconds since the Unix epoch.
    /// `captured_len` is how many bytes are actually present in `frame`; `original_len` is
    /// the on-the-wire length. `captured_len < original_len` means the snapshot length cut
    /// the frame short, which is normal on busy networks and is recorded rather than
    /// treated as an error.
    ///
    /// # Errors
    /// Returns [`DecodeError`] when the frame is too short to decode or a length field is
    /// inconsistent with the header it describes.
    pub fn decode(
        &self,
        frame: &[u8],
        timestamp_us: u64,
        captured_len: u32,
        original_len: u32,
    ) -> Result<NormalizedPacket, DecodeError> {
        if frame.len() < MIN_ETHERNET_FRAME_LEN {
            return Err(truncated("Ethernet", MIN_ETHERNET_FRAME_LEN, frame.len()));
        }

        let mut packet = NormalizedPacket {
            timestamp_us,
            captured_len,
            original_len,
            ethernet: None,
            vlan: None,
            arp: None,
            ip: None,
            transport: None,
            payload_offset: frame.len() as u32,
            payload_len: 0,
            truncated: captured_len < original_len,
            is_fragment: false,
        };

        let ethernet = decode_ethernet(frame, 0)?;
        packet.ethernet = Some(ethernet);

        let mut offset = ETHERNET_HEADER_LEN;
        let mut ethertype = ethernet.ethertype;

        if matches!(ethertype, ethertype::VLAN | ethertype::QINQ) {
            let vlan = decode_vlan(frame, offset)?;
            packet.vlan = Some(vlan.tag);
            ethertype = vlan.inner_ethertype;
            offset += VLAN_TAG_LEN;
        }

        match ethertype {
            ethertype::ARP => {
                packet.arp = Some(decode_arp(frame, offset)?);
            }
            ethertype::IPV4 => decode_ipv4(frame, offset, &mut packet)?,
            ethertype::IPV6 => decode_ipv6(frame, offset, &mut packet)?,
            // Unknown EtherType: keep the link header and leave every upper layer unset.
            _ => {}
        }

        Ok(packet)
    }
}

/// Reads a big-endian `u16`, or `None` past the end of `frame`.
fn read_u16(frame: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = frame.get(offset..end)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Reads a big-endian `u32`, or `None` past the end of `frame`.
fn read_u32(frame: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = frame.get(offset..end)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Copies six bytes as a MAC address, or `None` past the end of `frame`.
fn read_mac(frame: &[u8], offset: usize) -> Option<MacAddr> {
    let end = offset.checked_add(6)?;
    let bytes = frame.get(offset..end)?;
    let mut raw = [0u8; 6];
    raw.copy_from_slice(bytes);
    Some(MacAddr::from_bytes(raw))
}

/// Builds a truncation error for a specific layer.
fn truncated(layer: &'static str, needed: usize, available: usize) -> DecodeError {
    DecodeError::Truncated {
        layer,
        needed,
        available,
    }
}

/// Reads an IPv4 address, substituting zeroes when the frame is short.
///
/// Callers only reach this after a length check, so a short read here is already
/// reported as an error upstream.
fn read_ipv4(frame: &[u8], offset: usize) -> Ipv4Addr {
    let mut raw = [0u8; 4];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = frame.get(offset + index).copied().unwrap_or(0);
    }
    Ipv4Addr::from(raw)
}

/// Reads an IPv6 address, substituting zeroes when the frame is short.
fn read_ipv6(frame: &[u8], offset: usize) -> Ipv6Addr {
    let mut raw = [0u8; 16];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = frame.get(offset + index).copied().unwrap_or(0);
    }
    Ipv6Addr::from(raw)
}

/// Ethernet II decoding: destination, source, EtherType.
fn decode_ethernet(frame: &[u8], offset: usize) -> Result<EthernetFrame, DecodeError> {
    let available = frame.len().saturating_sub(offset);
    if available < ETHERNET_HEADER_LEN {
        return Err(truncated("Ethernet", ETHERNET_HEADER_LEN, available));
    }
    Ok(EthernetFrame {
        destination: read_mac(frame, offset)
            .ok_or_else(|| truncated("Ethernet", ETHERNET_HEADER_LEN, available))?,
        source: read_mac(frame, offset + 6)
            .ok_or_else(|| truncated("Ethernet", ETHERNET_HEADER_LEN, available))?,
        ethertype: read_u16(frame, offset + 12)
            .ok_or_else(|| truncated("Ethernet", ETHERNET_HEADER_LEN, available))?,
    })
}

/// An 802.1Q tag together with the EtherType it wraps.
///
/// The wrapped EtherType is kept here because decoding must continue through it, while the
/// public [`VlanTag`] model stays presentation-focused.
#[derive(Debug, Clone, Copy)]
struct DecodedVlan {
    tag: VlanTag,
    inner_ethertype: u16,
}

/// 802.1Q / 802.1ad decoding.
fn decode_vlan(frame: &[u8], offset: usize) -> Result<DecodedVlan, DecodeError> {
    let available = frame.len().saturating_sub(offset);
    let tci = read_u16(frame, offset).ok_or_else(|| truncated("VLAN", VLAN_TAG_LEN, available))?;
    let inner_ethertype =
        read_u16(frame, offset + 2).ok_or_else(|| truncated("VLAN", VLAN_TAG_LEN, available))?;

    Ok(DecodedVlan {
        tag: VlanTag {
            vlan_id: tci & 0x0fff,
            priority: ((tci >> 13) & 0x07) as u8,
            drop_eligible: (tci >> 12) & 0x01 == 1,
        },
        inner_ethertype,
    })
}

/// ARP decoding for Ethernet/IPv4.
///
/// Only that hardware/protocol combination is decoded. Other combinations carry
/// address sizes this model does not represent, so they are reported as an invalid length
/// rather than misread with IPv4 assumptions.
fn decode_arp(frame: &[u8], offset: usize) -> Result<ArpMessage, DecodeError> {
    let available = frame.len().saturating_sub(offset);
    if available < ARP_LEN {
        return Err(truncated("ARP", ARP_LEN, available));
    }

    let hardware_len = *frame
        .get(offset + 4)
        .ok_or_else(|| truncated("ARP", ARP_LEN, available))?;
    let protocol_len = *frame
        .get(offset + 5)
        .ok_or_else(|| truncated("ARP", ARP_LEN, available))?;
    if hardware_len != 6 || protocol_len != 4 {
        let value = (usize::from(hardware_len) << 8) | usize::from(protocol_len);
        return Err(DecodeError::InvalidLength {
            layer: "ARP",
            value,
        });
    }

    let opcode_raw =
        read_u16(frame, offset + 6).ok_or_else(|| truncated("ARP", ARP_LEN, available))?;

    Ok(ArpMessage {
        opcode: match opcode_raw {
            1 => ArpOpcode::Request,
            2 => ArpOpcode::Reply,
            other => ArpOpcode::Other(other),
        },
        hardware_type: read_u16(frame, offset)
            .ok_or_else(|| truncated("ARP", ARP_LEN, available))?,
        protocol_type: read_u16(frame, offset + 2)
            .ok_or_else(|| truncated("ARP", ARP_LEN, available))?,
        hardware_len,
        protocol_len,
        sender_mac: read_mac(frame, offset + 8)
            .ok_or_else(|| truncated("ARP", ARP_LEN, available))?,
        sender_ip: read_ipv4(frame, offset + 14),
        target_mac: read_mac(frame, offset + 18)
            .ok_or_else(|| truncated("ARP", ARP_LEN, available))?,
        target_ip: read_ipv4(frame, offset + 24),
    })
}

/// IPv4 decoding plus its transport header.
fn decode_ipv4(
    frame: &[u8],
    offset: usize,
    packet: &mut NormalizedPacket,
) -> Result<(), DecodeError> {
    let available = frame.len().saturating_sub(offset);
    let first = *frame
        .get(offset)
        .ok_or_else(|| truncated("IPv4", 1, available))?;

    let version = first >> 4;
    if version != 4 {
        return Err(DecodeError::UnsupportedIpVersion(version));
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < MIN_IPV4_LEN {
        return Err(DecodeError::InvalidLength {
            layer: "IPv4",
            value: ihl,
        });
    }
    if available < ihl {
        return Err(truncated("IPv4", ihl, available));
    }

    // Bits 15..=13 are flags, bits 12..=0 are the 13-bit fragment offset in 8-byte units.
    let flags_frag =
        read_u16(frame, offset + 6).ok_or_else(|| truncated("IPv4", ihl, available))?;

    packet.ip = Some(IpHeader::V4(Ipv4Header {
        source: read_ipv4(frame, offset + 12),
        destination: read_ipv4(frame, offset + 16),
        protocol: *frame
            .get(offset + 9)
            .ok_or_else(|| truncated("IPv4", ihl, available))?,
        ttl: *frame
            .get(offset + 8)
            .ok_or_else(|| truncated("IPv4", ihl, available))?,
        total_length: read_u16(frame, offset + 2)
            .ok_or_else(|| truncated("IPv4", ihl, available))?,
        dont_fragment: flags_frag & 0x4000 != 0,
        more_fragments: flags_frag & 0x2000 != 0,
        fragment_offset: flags_frag & 0x1fff,
        checksum: read_u16(frame, offset + 10).ok_or_else(|| truncated("IPv4", ihl, available))?,
    }));

    // A non-initial fragment carries no transport header. Flagging it here is what stops
    // the flow engine from inventing ports and splitting one flow into phantom flows.
    if flags_frag & 0x1fff != 0 {
        packet.is_fragment = true;
        return Ok(());
    }

    let transport_offset = offset + ihl;
    let declared = usize::from(read_u16(frame, offset + 2).unwrap_or_default()).saturating_sub(ihl);
    let available_transport = frame.len().saturating_sub(transport_offset);

    // An IPv4 total length equal to the header length means there is no payload at all, so
    // there is no transport header to decode. This is a bare-header frame, not an error.
    if declared == 0 {
        packet.payload_offset = transport_offset as u32;
        packet.payload_len = available_transport as u32;
        return Ok(());
    }

    // A snaplen-truncated frame can stop inside the transport header. That is a normal
    // consequence of the snapshot length, not a malformed packet, so the transport layer is
    // left unset instead of being counted as a decode error.
    let frame_was_truncated = available_transport < declared;
    let transport_len = declared.min(available_transport);

    let protocol = frame.get(offset + 9).copied().unwrap_or_default();
    if frame_was_truncated && available_transport < minimum_transport_len(protocol) {
        packet.payload_offset = transport_offset as u32;
        packet.payload_len = available_transport as u32;
        return Ok(());
    }
    decode_transport(frame, transport_offset, transport_len, protocol, packet)
}

/// Smallest transport header for a protocol number, used to decide whether a truncated
/// frame still contains a decodable header.
fn minimum_transport_len(protocol: u8) -> usize {
    match TransportProtocol::from_number(protocol) {
        TransportProtocol::Tcp => MIN_TCP_LEN,
        TransportProtocol::Udp => MIN_UDP_LEN,
        TransportProtocol::Icmp | TransportProtocol::IcmpV6 => MIN_ICMP_LEN,
        TransportProtocol::Other(_) => 0,
    }
}

/// IPv6 decoding plus its transport header.
fn decode_ipv6(
    frame: &[u8],
    offset: usize,
    packet: &mut NormalizedPacket,
) -> Result<(), DecodeError> {
    let available = frame.len().saturating_sub(offset);
    if available < IPV6_HEADER_LEN {
        return Err(truncated("IPv6", IPV6_HEADER_LEN, available));
    }
    let version = frame.get(offset).copied().unwrap_or_default() >> 4;
    if version != 6 {
        return Err(DecodeError::UnsupportedIpVersion(version));
    }

    packet.ip = Some(IpHeader::V6(Ipv6Header {
        source: read_ipv6(frame, offset + 8),
        destination: read_ipv6(frame, offset + 24),
        next_header: *frame
            .get(offset + 6)
            .ok_or_else(|| truncated("IPv6", IPV6_HEADER_LEN, available))?,
        hop_limit: *frame
            .get(offset + 7)
            .ok_or_else(|| truncated("IPv6", IPV6_HEADER_LEN, available))?,
        payload_length: read_u16(frame, offset + 4)
            .ok_or_else(|| truncated("IPv6", IPV6_HEADER_LEN, available))?,
        flow_label: read_u32(frame, offset).unwrap_or_default() & 0x000f_ffff,
    }));

    let transport_offset = offset + IPV6_HEADER_LEN;
    let declared = usize::from(read_u16(frame, offset + 4).unwrap_or_default());
    let available_transport = frame.len().saturating_sub(transport_offset);
    let frame_was_truncated = available_transport < declared;
    let transport_len = declared.min(available_transport);

    let next_header = frame.get(offset + 6).copied().unwrap_or_default();
    if frame_was_truncated && available_transport < minimum_transport_len(next_header) {
        packet.payload_offset = transport_offset as u32;
        packet.payload_len = available_transport as u32;
        return Ok(());
    }
    decode_transport(frame, transport_offset, transport_len, next_header, packet)
}

/// Decodes the transport header for a protocol number, recording payload geometry.
fn decode_transport(
    frame: &[u8],
    offset: usize,
    available: usize,
    protocol: u8,
    packet: &mut NormalizedPacket,
) -> Result<(), DecodeError> {
    let (header_len, transport): (usize, Option<TransportHeader>) =
        match TransportProtocol::from_number(protocol) {
            TransportProtocol::Tcp => {
                let tcp = decode_tcp(frame, offset, available)?;
                (
                    usize::from(tcp.header_length),
                    Some(TransportHeader::Tcp(tcp)),
                )
            }
            TransportProtocol::Udp => {
                let udp = decode_udp(frame, offset, available)?;
                (MIN_UDP_LEN, Some(TransportHeader::Udp(udp)))
            }
            TransportProtocol::Icmp => {
                let icmp = decode_icmp(frame, offset, available)?;
                (MIN_ICMP_LEN, Some(TransportHeader::Icmp(icmp)))
            }
            TransportProtocol::IcmpV6 => {
                let icmp = decode_icmp(frame, offset, available)?;
                (MIN_ICMP_LEN, Some(TransportHeader::IcmpV6(icmp)))
            }
            // Protocol numbers Sentinel does not decode still yield byte accounting, which is
            // what the flow engine needs.
            TransportProtocol::Other(_) => (0, None),
        };

    packet.transport = transport;
    packet.payload_offset = (offset + header_len) as u32;
    packet.payload_len = available.saturating_sub(header_len) as u32;
    Ok(())
}

/// TCP header decoding, including control bits and option count.
fn decode_tcp(frame: &[u8], offset: usize, available: usize) -> Result<TcpHeader, DecodeError> {
    if available < MIN_TCP_LEN {
        return Err(truncated("TCP", MIN_TCP_LEN, available));
    }
    let reserved_and_flags = *frame
        .get(offset + 12)
        .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?;
    let data_offset = usize::from(reserved_and_flags >> 4) * 4;
    if data_offset < MIN_TCP_LEN {
        return Err(DecodeError::InvalidLength {
            layer: "TCP",
            value: data_offset,
        });
    }
    let flags = *frame
        .get(offset + 13)
        .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?;

    Ok(TcpHeader {
        source_port: read_u16(frame, offset)
            .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?,
        destination_port: read_u16(frame, offset + 2)
            .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?,
        sequence: read_u32(frame, offset + 4)
            .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?,
        acknowledgement: read_u32(frame, offset + 8)
            .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?,
        flags: TcpFlags {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
            ece: flags & 0x40 != 0,
            cwr: flags & 0x80 != 0,
            ns: reserved_and_flags & 0x01 != 0,
        },
        window: read_u16(frame, offset + 14)
            .ok_or_else(|| truncated("TCP", MIN_TCP_LEN, available))?,
        header_length: data_offset as u8,
        option_count: count_tcp_options(frame, offset + MIN_TCP_LEN, offset + data_offset),
        payload_length: available.saturating_sub(data_offset) as u16,
    })
}

/// Counts TCP options by walking the kind/length chain.
///
/// Sentinel needs an option *count* for display and future detection, not a full option
/// decode, so a malformed chain stops at the first inconsistency instead of erroring.
fn count_tcp_options(frame: &[u8], start: usize, end: usize) -> u8 {
    let mut offset = start;
    let mut count = 0u8;
    while offset < end {
        let Some(kind) = frame.get(offset).copied() else {
            break;
        };
        match kind {
            0 => break,       // end of option list
            1 => offset += 1, // NOP occupies a single byte
            _ => {
                let Some(len) = frame.get(offset + 1).copied() else {
                    break;
                };
                let len = usize::from(len);
                if len < 2 {
                    break;
                }
                offset += len;
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// UDP header decoding.
fn decode_udp(frame: &[u8], offset: usize, available: usize) -> Result<UdpHeader, DecodeError> {
    if available < MIN_UDP_LEN {
        return Err(truncated("UDP", MIN_UDP_LEN, available));
    }
    Ok(UdpHeader {
        source_port: read_u16(frame, offset)
            .ok_or_else(|| truncated("UDP", MIN_UDP_LEN, available))?,
        destination_port: read_u16(frame, offset + 2)
            .ok_or_else(|| truncated("UDP", MIN_UDP_LEN, available))?,
        length: read_u16(frame, offset + 4)
            .ok_or_else(|| truncated("UDP", MIN_UDP_LEN, available))?,
    })
}

/// ICMP / ICMPv6 type and code decoding.
fn decode_icmp(frame: &[u8], offset: usize, available: usize) -> Result<IcmpHeader, DecodeError> {
    if available < MIN_ICMP_LEN {
        return Err(truncated("ICMP", MIN_ICMP_LEN, available));
    }
    Ok(IcmpHeader {
        icmp_type: *frame
            .get(offset)
            .ok_or_else(|| truncated("ICMP", MIN_ICMP_LEN, available))?,
        code: *frame
            .get(offset + 1)
            .ok_or_else(|| truncated("ICMP", MIN_ICMP_LEN, available))?,
    })
}

/// Source endpoint of a decoded packet, for flow keying.
#[must_use]
pub fn source_endpoint(packet: &NormalizedPacket) -> Option<(IpAddr, Option<u16>)> {
    Some((packet.src_ip()?, packet.src_port()))
}

/// Destination endpoint of a decoded packet, for flow keying.
#[must_use]
pub fn dest_endpoint(packet: &NormalizedPacket) -> Option<(IpAddr, Option<u16>)> {
    Some((packet.dst_ip()?, packet.dst_port()))
}
