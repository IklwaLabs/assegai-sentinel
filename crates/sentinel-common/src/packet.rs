//! The normalized packet model.
//!
//! `NormalizedPacket` is what the parser produces and everything downstream consumes.
//! It is deliberately not a mirror of any wire format: it keeps only what Sentinel uses
//! for flow accounting, protocol classification and later detection.
//!
//! Invariants:
//! - Every `Option` is `None` when the layer was absent or could not be decoded.
//! - Accessors ([`NormalizedPacket::src_ip`], [`NormalizedPacket::dst_port`], ...) hide
//!   the `match` so downstream code never needs to know the layer nesting.
//! - Payload bytes are **not** retained. Only the payload offset and length are kept so
//!   a protocol decoder can be layered on later without re-walking the frame.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::net::MacAddr;

/// EtherType value, kept as the raw number so unknown types remain visible.
pub mod ethertype {
    /// IPv4.
    pub const IPV4: u16 = 0x0800;
    /// ARP.
    pub const ARP: u16 = 0x0806;
    /// IPv6.
    pub const IPV6: u16 = 0x86dd;
    /// VLAN-tagged frame (802.1Q).
    pub const VLAN: u16 = 0x8100;
    /// Double-tagged frame (802.1ad).
    pub const QINQ: u16 = 0x88a8;
    /// PPP over Ethernet discovery stage.
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    /// PPP over Ethernet session stage.
    pub const PPPOE_SESSION: u16 = 0x8864;
}

/// An 802.1Q VLAN tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VlanTag {
    /// 12-bit VLAN identifier.
    pub vlan_id: u16,
    /// Priority code point (0-7).
    pub priority: u8,
    /// Whether the canonical frame bit was set.
    pub drop_eligible: bool,
}

/// Ethernet II header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthernetFrame {
    /// Destination hardware address.
    pub destination: MacAddr,
    /// Source hardware address.
    pub source: MacAddr,
    /// EtherType of the encapsulated payload.
    pub ethertype: u16,
}

/// ARP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArpOpcode {
    /// ARP request: "who has X, tell Y".
    Request,
    /// ARP reply.
    Reply,
    /// Any other opcode, preserved numerically.
    Other(u16),
}

/// A decoded ARP message (IPv4 over Ethernet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpMessage {
    /// Request or reply.
    pub opcode: ArpOpcode,
    /// Hardware type; 1 is Ethernet.
    pub hardware_type: u16,
    /// Protocol type; 0x0800 is IPv4.
    pub protocol_type: u16,
    /// Hardware address length in bytes.
    pub hardware_len: u8,
    /// Protocol address length in bytes.
    pub protocol_len: u8,
    /// Sender hardware address.
    pub sender_mac: MacAddr,
    /// Sender protocol address.
    pub sender_ip: Ipv4Addr,
    /// Target hardware address (zero in requests).
    pub target_mac: MacAddr,
    /// Target protocol address.
    pub target_ip: Ipv4Addr,
}

impl ArpMessage {
    /// True when this is an ARP reply.
    #[must_use]
    pub const fn is_reply(&self) -> bool {
        matches!(self.opcode, ArpOpcode::Reply)
    }
}

/// IPv4 header fields Sentinel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4Header {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// Transport protocol number.
    pub protocol: u8,
    /// Time to live / hop limit.
    pub ttl: u8,
    /// Total length in bytes as declared by the sender.
    pub total_length: u16,
    /// Don't fragment flag.
    pub dont_fragment: bool,
    /// More fragments flag.
    pub more_fragments: bool,
    /// Fragment offset in bytes.
    pub fragment_offset: u16,
    /// Header checksum as received; zero means "not verified".
    pub checksum: u16,
}

/// IPv6 header fields Sentinel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6Header {
    /// Source address.
    pub source: Ipv6Addr,
    /// Destination address.
    pub destination: Ipv6Addr,
    /// Next header (or extension header) value.
    pub next_header: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Payload length in bytes as declared by the sender.
    pub payload_length: u16,
    /// Flow label.
    pub flow_label: u32,
}

/// Either IP version, without the layer-specific header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "version", content = "header")]
pub enum IpHeader {
    /// IPv4 header.
    V4(Ipv4Header),
    /// IPv6 header.
    V6(Ipv6Header),
}

impl IpHeader {
    /// Source address of the packet.
    #[must_use]
    pub const fn source(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.source),
            IpHeader::V6(h) => IpAddr::V6(h.source),
        }
    }

    /// Destination address of the packet.
    #[must_use]
    pub const fn destination(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.destination),
            IpHeader::V6(h) => IpAddr::V6(h.destination),
        }
    }

    /// Transport protocol number of the packet.
    #[must_use]
    pub const fn protocol(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.protocol,
            IpHeader::V6(h) => h.next_header,
        }
    }

    /// Hop limit / TTL.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.ttl,
            IpHeader::V6(h) => h.hop_limit,
        }
    }
}

/// Transport protocol classification used by the flow engine.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum TransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// ICMPv4.
    Icmp,
    /// ICMPv6.
    IcmpV6,
    /// Any other protocol number, preserved numerically.
    Other(u8),
}

impl Default for TransportProtocol {
    /// `Other(0)` is the IP protocol number reserved as "hop-by-hop", which is the neutral
    /// choice for a zero-initialized aggregate row.
    fn default() -> Self {
        TransportProtocol::Other(0)
    }
}

impl TransportProtocol {
    /// Maps an IP protocol number to a transport protocol.
    #[must_use]
    pub const fn from_number(number: u8) -> Self {
        match number {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            1 => TransportProtocol::Icmp,
            58 => TransportProtocol::IcmpV6,
            other => TransportProtocol::Other(other),
        }
    }

    /// The IP protocol number.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
            TransportProtocol::Icmp => 1,
            TransportProtocol::IcmpV6 => 58,
            TransportProtocol::Other(n) => n,
        }
    }

    /// Whether this protocol has source and destination ports.
    #[must_use]
    pub const fn has_ports(self) -> bool {
        matches!(self, TransportProtocol::Tcp | TransportProtocol::Udp)
    }

    /// Short uppercase label used in tables and charts.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Icmp => "ICMP",
            TransportProtocol::IcmpV6 => "ICMPv6",
            TransportProtocol::Other(_) => "Other",
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportProtocol::Other(n) => write!(f, "IP({n})"),
            other => f.write_str(other.label()),
        }
    }
}

/// TCP control bits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpFlags {
    /// FIN.
    pub fin: bool,
    /// SYN.
    pub syn: bool,
    /// RST.
    pub rst: bool,
    /// PSH.
    pub psh: bool,
    /// ACK.
    pub ack: bool,
    /// URG.
    pub urg: bool,
    /// ECE.
    pub ece: bool,
    /// CWR.
    pub cwr: bool,
    /// NS (RFC 3168 ECN-nonce).
    pub ns: bool,
}

/// Decoded TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpHeader {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Sequence number.
    pub sequence: u32,
    /// Acknowledgement number.
    pub acknowledgement: u32,
    /// Control bits.
    pub flags: TcpFlags,
    /// Advertised receive window.
    pub window: u16,
    /// Header length in bytes.
    pub header_length: u8,
    /// Number of TCP options present.
    pub option_count: u8,
    /// TCP payload length in bytes.
    pub payload_length: u16,
}

/// Decoded UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpHeader {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Length including the 8-byte header.
    pub length: u16,
}

/// Decoded ICMP / ICMPv6 header (type and code only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IcmpHeader {
    /// ICMP type.
    pub icmp_type: u8,
    /// ICMP code.
    pub code: u8,
}

/// Decoded transport layer information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "header")]
pub enum TransportHeader {
    /// TCP.
    Tcp(TcpHeader),
    /// UDP.
    Udp(UdpHeader),
    /// ICMPv4.
    Icmp(IcmpHeader),
    /// ICMPv6.
    IcmpV6(IcmpHeader),
}

/// A decoded packet, normalized across link types.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedPacket {
    /// Capture timestamp in microseconds since the Unix epoch.
    pub timestamp_us: u64,
    /// Bytes actually captured.
    pub captured_len: u32,
    /// Bytes on the wire (larger than `captured_len` when snaplen truncated the frame).
    pub original_len: u32,
    /// Ethernet header, when the capture source used Ethernet framing.
    #[serde(default)]
    pub ethernet: Option<EthernetFrame>,
    /// VLAN tag, when present.
    #[serde(default)]
    pub vlan: Option<VlanTag>,
    /// ARP message, when present.
    #[serde(default)]
    pub arp: Option<ArpMessage>,
    /// IP header, when present.
    #[serde(default)]
    pub ip: Option<IpHeader>,
    /// Transport header, when present and the payload started at a header boundary.
    #[serde(default)]
    pub transport: Option<TransportHeader>,
    /// Byte offset of application payload within the captured frame.
    pub payload_offset: u32,
    /// Application payload length in bytes.
    pub payload_len: u32,
    /// True when snaplen truncated the frame.
    pub truncated: bool,
    /// True when this is a non-initial IP fragment.
    pub is_fragment: bool,
}

impl NormalizedPacket {
    /// Source IP address, if the packet carried IP.
    #[must_use]
    pub fn src_ip(&self) -> Option<IpAddr> {
        self.ip.map(|ip| ip.source())
    }

    /// Destination IP address, if the packet carried IP.
    #[must_use]
    pub fn dst_ip(&self) -> Option<IpAddr> {
        self.ip.map(|ip| ip.destination())
    }

    /// Transport protocol, defaulting to `Other(255)` for non-IP frames.
    #[must_use]
    pub fn transport_protocol(&self) -> TransportProtocol {
        self.ip
            .map(|ip| TransportProtocol::from_number(ip.protocol()))
            .unwrap_or(TransportProtocol::Other(255))
    }

    /// Source port, when the transport protocol uses ports.
    #[must_use]
    pub fn src_port(&self) -> Option<u16> {
        match self.transport? {
            TransportHeader::Tcp(t) => Some(t.source_port),
            TransportHeader::Udp(u) => Some(u.source_port),
            _ => None,
        }
    }

    /// Destination port, when the transport protocol uses ports.
    #[must_use]
    pub fn dst_port(&self) -> Option<u16> {
        match self.transport? {
            TransportHeader::Tcp(t) => Some(t.destination_port),
            TransportHeader::Udp(u) => Some(u.destination_port),
            _ => None,
        }
    }

    /// True when this frame carried IPv4 or IPv6.
    #[must_use]
    pub const fn is_ip(&self) -> bool {
        self.ip.is_some()
    }

    /// True when the packet was captured with a snaplen smaller than the wire length.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated || self.captured_len < self.original_len
    }

    /// Bytes on the wire attributable to this packet, used for flow byte counters.
    #[must_use]
    pub const fn wire_len(&self) -> u64 {
        self.original_len as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_packet() -> NormalizedPacket {
        NormalizedPacket {
            timestamp_us: 1_735_689_600_000_000,
            captured_len: 74,
            original_len: 74,
            ethernet: Some(EthernetFrame {
                destination: MacAddr::from_bytes([0xff; 6]),
                source: MacAddr::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                ethertype: ethertype::IPV4,
            }),
            vlan: None,
            arp: None,
            ip: Some(IpHeader::V4(Ipv4Header {
                source: "192.168.1.10".parse().expect("valid source"),
                destination: "93.184.216.34".parse().expect("valid destination"),
                protocol: 6,
                ttl: 128,
                total_length: 40,
                dont_fragment: true,
                more_fragments: false,
                fragment_offset: 0,
                checksum: 0x1234,
            })),
            transport: Some(TransportHeader::Tcp(TcpHeader {
                source_port: 52_341,
                destination_port: 443,
                sequence: 1,
                acknowledgement: 0,
                flags: TcpFlags {
                    syn: true,
                    ..TcpFlags::default()
                },
                window: 64_240,
                header_length: 20,
                option_count: 2,
                payload_length: 0,
            })),
            payload_offset: 54,
            payload_len: 0,
            truncated: false,
            is_fragment: false,
        }
    }

    #[test]
    fn accessors_hide_layer_nesting() {
        let packet = ipv4_tcp_packet();
        assert_eq!(
            packet.src_ip().map(|a| a.to_string()).as_deref(),
            Some("192.168.1.10")
        );
        assert_eq!(
            packet.dst_ip().map(|a| a.to_string()).as_deref(),
            Some("93.184.216.34")
        );
        assert_eq!(packet.transport_protocol(), TransportProtocol::Tcp);
        assert_eq!(packet.src_port(), Some(52_341));
        assert_eq!(packet.dst_port(), Some(443));
        assert!(packet.is_ip());
        assert!(!packet.is_truncated());
        assert_eq!(packet.wire_len(), 74);
    }

    #[test]
    fn protocol_mapping_is_reversible() {
        for proto in [
            TransportProtocol::Tcp,
            TransportProtocol::Udp,
            TransportProtocol::Icmp,
            TransportProtocol::IcmpV6,
        ] {
            assert_eq!(TransportProtocol::from_number(proto.number()), proto);
        }
        assert_eq!(
            TransportProtocol::from_number(132),
            TransportProtocol::Other(132)
        );
        assert_eq!(TransportProtocol::Other(132).number(), 132);
        assert!(TransportProtocol::Tcp.has_ports());
        assert!(!TransportProtocol::Icmp.has_ports());
        assert_eq!(TransportProtocol::Udp.to_string(), "UDP");
        assert_eq!(TransportProtocol::Other(132).to_string(), "IP(132)");
    }

    #[test]
    fn truncation_is_detected_from_lengths() {
        let mut packet = ipv4_tcp_packet();
        packet.captured_len = 54;
        assert!(packet.is_truncated());
    }

    #[test]
    fn icmp_packets_expose_no_ports() {
        let packet = NormalizedPacket {
            ip: Some(IpHeader::V4(Ipv4Header {
                source: "10.0.0.5".parse().expect("valid source"),
                destination: "10.0.0.1".parse().expect("valid destination"),
                protocol: 1,
                ttl: 64,
                total_length: 28,
                dont_fragment: false,
                more_fragments: false,
                fragment_offset: 0,
                checksum: 0,
            })),
            transport: Some(TransportHeader::Icmp(IcmpHeader {
                icmp_type: 8,
                code: 0,
            })),
            ..NormalizedPacket {
                timestamp_us: 0,
                captured_len: 42,
                original_len: 42,
                ethernet: None,
                vlan: None,
                arp: None,
                ip: None,
                transport: None,
                payload_offset: 34,
                payload_len: 0,
                truncated: false,
                is_fragment: false,
            }
        };
        assert_eq!(packet.transport_protocol(), TransportProtocol::Icmp);
        assert_eq!(packet.src_port(), None);
        assert_eq!(packet.dst_port(), None);
    }

    #[test]
    fn arp_reply_detection() {
        let msg = ArpMessage {
            opcode: ArpOpcode::Reply,
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: 6,
            protocol_len: 4,
            sender_mac: MacAddr::from_bytes([1; 6]),
            sender_ip: Ipv4Addr::new(192, 168, 1, 1),
            target_mac: MacAddr::ZERO,
            target_ip: Ipv4Addr::new(192, 168, 1, 10),
        };
        assert!(msg.is_reply());
    }
}
