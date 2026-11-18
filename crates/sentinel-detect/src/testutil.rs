//! Packet builders shared by the detector tests.
//!
//! Detection rules are only as good as the traffic they are tested against, and a test that
//! builds a packet by hand in each module drifts: one module sets `ack`, another forgets
//! `protocol`, and a rule that looks tested is not. These builders produce one complete,
//! internally consistent packet, so a test states only the fields that matter to it.

use std::net::IpAddr;

use sentinel_common::net::MacAddr;
use sentinel_common::packet::{
    ArpMessage, ArpOpcode, IpHeader, Ipv4Header, NormalizedPacket, TcpFlags, TcpHeader,
    TransportHeader, TransportProtocol, UdpHeader,
};

/// Control bits for a client's initial SYN.
pub(crate) fn syn() -> TcpFlags {
    TcpFlags {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    }
}

/// Control bits for a server's SYN+ACK.
pub(crate) fn syn_ack() -> TcpFlags {
    let mut flags = syn();
    flags.ack = true;
    flags
}

/// Control bits for ordinary data.
pub(crate) fn ack() -> TcpFlags {
    let mut flags = syn();
    flags.syn = false;
    flags.ack = true;
    flags
}

/// A TCP packet between two addresses.
pub(crate) fn tcp_packet(
    source: &str,
    destination: &str,
    source_port: u16,
    destination_port: u16,
    flags: TcpFlags,
    timestamp_us: u64,
) -> NormalizedPacket {
    tcp_packet_with_payload(
        source,
        destination,
        source_port,
        destination_port,
        flags,
        timestamp_us,
        0,
    )
}

/// A TCP packet carrying `payload_len` bytes of application data.
pub(crate) fn tcp_packet_with_payload(
    source: &str,
    destination: &str,
    source_port: u16,
    destination_port: u16,
    flags: TcpFlags,
    timestamp_us: u64,
    payload_len: u32,
) -> NormalizedPacket {
    let header_len = 20u32;
    let total = header_len + payload_len;
    NormalizedPacket {
        timestamp_us,
        captured_len: total,
        original_len: total,
        ethernet: None,
        vlan: None,
        arp: None,
        ip: Some(IpHeader::V4(Ipv4Header {
            source: parse_v4(source),
            destination: parse_v4(destination),
            protocol: 6,
            ttl: 64,
            total_length: u16::try_from(total).unwrap_or(u16::MAX),
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            checksum: 0,
        })),
        transport: Some(TransportHeader::Tcp(TcpHeader {
            source_port,
            destination_port,
            sequence: 1,
            acknowledgement: 0,
            flags,
            window: 64_240,
            header_length: 20,
            option_count: 0,
            payload_length: u16::try_from(payload_len).unwrap_or(u16::MAX),
        })),
        payload_offset: header_len,
        payload_len,
        truncated: false,
        is_fragment: false,
    }
}

/// A UDP packet carrying `payload_len` bytes.
pub(crate) fn udp_packet(
    source: &str,
    destination: &str,
    source_port: u16,
    destination_port: u16,
    timestamp_us: u64,
    payload_len: u32,
) -> NormalizedPacket {
    let header_len = 8u32;
    let total = header_len + payload_len;
    NormalizedPacket {
        timestamp_us,
        captured_len: total,
        original_len: total,
        ethernet: None,
        vlan: None,
        arp: None,
        ip: Some(IpHeader::V4(Ipv4Header {
            source: parse_v4(source),
            destination: parse_v4(destination),
            protocol: 17,
            ttl: 64,
            total_length: u16::try_from(total).unwrap_or(u16::MAX),
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            checksum: 0,
        })),
        transport: Some(TransportHeader::Udp(UdpHeader {
            source_port,
            destination_port,
            length: u16::try_from(total).unwrap_or(u16::MAX),
        })),
        payload_offset: header_len,
        payload_len,
        truncated: false,
        is_fragment: false,
    }
}

/// The transport protocol a packet carries, for tests that assert on it.
pub(crate) fn protocol_of(packet: &NormalizedPacket) -> TransportProtocol {
    packet.transport_protocol()
}

/// An ARP reply claiming `sender_ip` for `sender_mac`.
pub(crate) fn arp_reply(
    sender_mac: [u8; 6],
    sender_ip: &str,
    target_mac: [u8; 6],
    target_ip: &str,
) -> ArpMessage {
    ArpMessage {
        opcode: ArpOpcode::Reply,
        hardware_type: 1,
        protocol_type: 0x0800,
        hardware_len: 6,
        protocol_len: 4,
        sender_mac: MacAddr::from_bytes(sender_mac),
        sender_ip: sender_ip
            .parse()
            .unwrap_or_else(|_| panic!("{sender_ip} is not a valid IPv4 address")),
        target_mac: MacAddr::from_bytes(target_mac),
        target_ip: target_ip
            .parse()
            .unwrap_or_else(|_| panic!("{target_ip} is not a valid IPv4 address")),
    }
}

/// A frame carrying an ARP message.
pub(crate) fn arp_packet(arp: ArpMessage, timestamp_us: u64) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_us,
        captured_len: 42,
        original_len: 42,
        ethernet: None,
        vlan: None,
        arp: Some(arp),
        ip: None,
        transport: None,
        payload_offset: 42,
        payload_len: 0,
        truncated: false,
        is_fragment: false,
    }
}

/// Parses a test address, panicking with the offending text when it is not valid.
pub(crate) fn addr(text: &str) -> IpAddr {
    text.parse()
        .unwrap_or_else(|_| panic!("{text} is not a valid address"))
}

fn parse_v4(text: &str) -> std::net::Ipv4Addr {
    text.parse()
        .unwrap_or_else(|_| panic!("{text} is not a valid IPv4 address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_packet_is_internally_consistent() {
        let packet =
            tcp_packet_with_payload("10.0.0.5", "93.184.216.34", 51_000, 443, syn(), 42, 100);
        assert_eq!(packet.timestamp_us, 42);
        assert_eq!(packet.payload_len, 100);
        assert_eq!(packet.src_ip(), Some(addr("10.0.0.5")));
        assert_eq!(packet.dst_port(), Some(443));
        assert_eq!(protocol_of(&packet), TransportProtocol::Tcp);
        assert!(!packet.is_fragment);
    }

    #[test]
    fn the_three_flag_presets_differ_only_where_they_should() {
        assert!(syn().syn && !syn().ack);
        assert!(syn_ack().syn && syn_ack().ack);
        assert!(!ack().syn && ack().ack);
    }

    #[test]
    fn a_udp_packet_reports_udp() {
        let packet = udp_packet("10.0.0.5", "8.8.8.8", 51_000, 53, 1, 30);
        assert_eq!(protocol_of(&packet), TransportProtocol::Udp);
        assert_eq!(packet.dst_port(), Some(53));
    }

    #[test]
    fn an_ipv6_build_is_not_attempted_with_the_ipv4_helper() {
        // The helper is IPv4-only on purpose: a test that mixes families by accident should
        // fail loudly here rather than produce a packet with the wrong source family.
        assert!(std::panic::catch_unwind(|| parse_v4("2001:db8::1")).is_err());
    }
}
