//! Decoder tests.
//!
//! Frames come from the [`fixtures`] module, which builds them byte-by-byte so each test
//! states exactly which header field it exercises. That keeps these tests honest: they
//! describe the wire format, not the decoder's own output.

use std::net::Ipv4Addr;

use sentinel_common::net::MacAddr;
use sentinel_common::packet::{ArpOpcode, IpHeader, TransportHeader, TransportProtocol, ethertype};

use super::decode::{DecodeError, PacketDecoder};
use super::fixtures;

/// Fixed timestamp used across tests: 2025-01-01T00:00:00Z.
const TIMESTAMP_US: u64 = 1_735_689_600_000_000;

/// Decodes a frame with the test decoder, treating decode failure as a test failure.
fn decode(frame: &[u8]) -> sentinel_common::packet::NormalizedPacket {
    PacketDecoder::new()
        .decode(frame, TIMESTAMP_US, frame.len() as u32, frame.len() as u32)
        .unwrap_or_else(|err| panic!("frame should decode: {err}"))
}

#[test]
fn decodes_ethernet_header() {
    // An Ethernet header with a complete IPv4 header after it: the link layer is decoded
    // independently of whether an upper layer is present.
    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.extend_from_slice(&fixtures::ipv4_header(
        6,
        20,
        0x4000,
        fixtures::SRC_IP,
        fixtures::DST_IP,
    ));

    let packet = decode(&frame);
    let eth = packet.ethernet.expect("ethernet header");
    assert_eq!(eth.source, MacAddr::from_bytes(fixtures::SRC_MAC));
    assert_eq!(eth.destination, MacAddr::from_bytes(fixtures::DST_MAC));
    assert_eq!(eth.ethertype, ethertype::IPV4);
}

#[test]
fn decodes_arp_request() {
    let packet = decode(&fixtures::arp_request_frame());
    let arp = packet.arp.expect("arp message");
    assert_eq!(arp.opcode, ArpOpcode::Request);
    assert_eq!(arp.sender_mac, MacAddr::from_bytes(fixtures::SRC_MAC));
    assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(arp.target_mac, MacAddr::ZERO);
    assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(arp.hardware_len, 6);
    assert_eq!(arp.protocol_len, 4);
    // ARP carries no IP or transport layer, and none is invented.
    assert!(packet.ip.is_none());
    assert!(packet.transport.is_none());
}

#[test]
fn decodes_arp_reply() {
    let packet = decode(&fixtures::arp_reply_frame());
    let arp = packet.arp.expect("arp message");
    assert_eq!(arp.opcode, ArpOpcode::Reply);
    assert!(arp.is_reply());
    assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(
        arp.sender_mac,
        MacAddr::from_bytes([0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc])
    );
}

#[test]
fn decodes_ipv4_tcp_with_flags() {
    let packet = decode(&fixtures::tcp_frame(52_341, 443, 0x02, &[]));

    match packet.ip.expect("ipv4 header") {
        IpHeader::V4(ip) => {
            assert_eq!(ip.source, Ipv4Addr::new(192, 168, 1, 10));
            assert_eq!(ip.destination, Ipv4Addr::new(93, 184, 216, 34));
            assert_eq!(ip.protocol, 6);
            assert_eq!(ip.ttl, 64);
            assert_eq!(ip.total_length, 40);
            assert!(ip.dont_fragment);
            assert!(!ip.more_fragments);
            assert_eq!(ip.fragment_offset, 0);
        }
        other => panic!("expected IPv4, got {other:?}"),
    }

    match packet.transport.expect("tcp header") {
        TransportHeader::Tcp(tcp) => {
            assert_eq!(tcp.source_port, 52_341);
            assert_eq!(tcp.destination_port, 443);
            assert!(tcp.flags.syn, "SYN bit");
            assert!(!tcp.flags.ack, "ACK bit");
            assert_eq!(tcp.sequence, 1000);
            assert_eq!(tcp.acknowledgement, 2000);
            assert_eq!(tcp.window, 64_240);
            assert_eq!(tcp.header_length, 20);
            assert_eq!(tcp.option_count, 0);
        }
        other => panic!("expected TCP, got {other:?}"),
    }

    assert_eq!(packet.transport_protocol(), TransportProtocol::Tcp);
    assert_eq!(packet.src_port(), Some(52_341));
    assert_eq!(packet.dst_port(), Some(443));
    assert!(!packet.is_fragment);
}

#[test]
fn counts_tcp_options() {
    // A 4-byte MSS option makes a 24-byte TCP header, so IPv4 declares 44 payload bytes.
    let mut ip = fixtures::ipv4_header(6, 44, 0x4000, fixtures::SRC_IP, fixtures::DST_IP);
    ip.extend_from_slice(&fixtures::tcp_header_with_options(
        1,
        2,
        &[2, 4, 0x05, 0xb4],
    ));

    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.extend_from_slice(&ip);

    match decode(&frame).transport.expect("tcp header") {
        TransportHeader::Tcp(tcp) => {
            assert_eq!(tcp.header_length, 24);
            assert_eq!(tcp.option_count, 1, "one MSS option");
        }
        other => panic!("expected TCP, got {other:?}"),
    }
}

#[test]
fn stops_counting_options_at_a_malformed_length() {
    // A zero length byte in the option chain must terminate the walk, not loop.
    let mut ip = fixtures::ipv4_header(6, 44, 0x4000, fixtures::SRC_IP, fixtures::DST_IP);
    ip.extend_from_slice(&fixtures::tcp_header_with_options(1, 2, &[2, 0, 2, 4]));

    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.extend_from_slice(&ip);

    match decode(&frame).transport.expect("tcp header") {
        TransportHeader::Tcp(tcp) => assert_eq!(tcp.option_count, 0),
        other => panic!("expected TCP, got {other:?}"),
    }
}

#[test]
fn decodes_udp_and_reports_payload_geometry() {
    let payload = fixtures::dns_query_payload(0x1234, "example.com", 1);
    let frame = fixtures::udp_frame(53_000, 53, &payload);
    let packet = decode(&frame);

    match packet.transport.expect("udp header") {
        TransportHeader::Udp(udp) => {
            assert_eq!(udp.source_port, 53_000);
            assert_eq!(udp.destination_port, 53);
            assert_eq!(udp.length as usize, 8 + payload.len());
        }
        other => panic!("expected UDP, got {other:?}"),
    }
    assert_eq!(packet.transport_protocol(), TransportProtocol::Udp);
    assert_eq!(packet.payload_offset as usize, 14 + 20 + 8);
    assert_eq!(packet.payload_len as usize, payload.len());
}

#[test]
fn decodes_icmp_without_ports() {
    let packet = decode(&fixtures::icmp_echo_frame());
    assert_eq!(packet.transport_protocol(), TransportProtocol::Icmp);
    match packet.transport.expect("icmp header") {
        TransportHeader::Icmp(icmp) => {
            assert_eq!(icmp.icmp_type, 8);
            assert_eq!(icmp.code, 0);
        }
        other => panic!("expected ICMP, got {other:?}"),
    }
    assert_eq!(packet.src_port(), None);
    assert_eq!(packet.dst_port(), None);
}

#[test]
fn decodes_ipv6_tcp() {
    let packet = decode(&fixtures::ipv6_tcp_frame(49_152, 443, 0x02));
    match packet.ip.expect("ipv6 header") {
        IpHeader::V6(ip) => {
            assert_eq!(ip.source.to_string(), "fd00::1");
            assert_eq!(ip.destination.to_string(), "2606:4700::6810");
            assert_eq!(ip.next_header, 6);
            assert_eq!(ip.hop_limit, 64);
            assert_eq!(ip.payload_length, 20);
        }
        other => panic!("expected IPv6, got {other:?}"),
    }
    assert_eq!(packet.dst_port(), Some(443));
    assert_eq!(packet.transport_protocol(), TransportProtocol::Tcp);
}

#[test]
fn decodes_vlan_tagged_frames() {
    let packet = decode(&fixtures::vlan_udp_frame(100, 3, 1_234, 53));
    let vlan = packet.vlan.expect("vlan tag");
    assert_eq!(vlan.vlan_id, 100);
    assert_eq!(vlan.priority, 3);
    assert!(!vlan.drop_eligible);
    // The wrapped EtherType was followed, so the IP and UDP headers were still decoded.
    assert_eq!(packet.src_port(), Some(1_234));
    assert_eq!(packet.payload_offset as usize, 14 + 4 + 20 + 8);
}

#[test]
fn non_initial_ipv4_fragments_do_not_produce_ports() {
    let packet = decode(&fixtures::ipv4_non_initial_fragment(185));
    assert!(packet.is_fragment, "non-initial fragment must be flagged");
    assert!(
        packet.transport.is_none(),
        "a fragment has no transport header"
    );
    assert_eq!(packet.src_port(), None);
    assert_eq!(packet.dst_port(), None);
}

#[test]
fn reports_truncation_from_snaplen() {
    let full = fixtures::tcp_frame(52_341, 443, 0x18, b"hello world");
    // Cut inside the payload: both headers are complete, so ports remain available.
    let captured_len = full.len() as u32 - 5;

    let packet = PacketDecoder::new()
        .decode(
            &full[..captured_len as usize],
            TIMESTAMP_US,
            captured_len,
            full.len() as u32,
        )
        .expect("a snaplen-truncated frame still decodes its headers");

    assert!(packet.truncated);
    assert!(packet.is_truncated());
    assert_eq!(packet.captured_len, captured_len);
    assert_eq!(packet.original_len, full.len() as u32);
    assert_eq!(packet.dst_port(), Some(443));
    assert_eq!(packet.src_port(), Some(52_341));
}

#[test]
fn unknown_ethertype_is_kept_without_error() {
    let mut frame = fixtures::ethernet(0x88b5); // Local Experimental Ethertype
    frame.extend_from_slice(&[0u8; 20]);
    let packet = decode(&frame);
    assert!(packet.ip.is_none());
    assert!(packet.transport.is_none());
    assert_eq!(packet.ethernet.expect("ethernet").ethertype, 0x88b5);
}

#[test]
fn rejects_frames_shorter_than_the_ethernet_header() {
    let err = PacketDecoder::new()
        .decode(&[0xff; 10], TIMESTAMP_US, 10, 10)
        .expect_err("a short frame must fail");
    assert_eq!(
        err,
        DecodeError::Truncated {
            layer: "Ethernet",
            needed: 14,
            available: 10
        }
    );
}

#[test]
fn rejects_bad_ipv4_header_length() {
    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.push(0x44); // version 4, IHL 4 (16 bytes) below the 20-byte minimum
    frame.extend_from_slice(&[0u8; 19]);

    let err = PacketDecoder::new()
        .decode(&frame, TIMESTAMP_US, frame.len() as u32, frame.len() as u32)
        .expect_err("an invalid IHL must fail");
    assert!(
        matches!(err, DecodeError::InvalidLength { layer: "IPv4", .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_non_ipv4_version_bytes() {
    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.push(0x55); // version 5
    frame.extend_from_slice(&[0u8; 19]);

    let err = PacketDecoder::new()
        .decode(&frame, TIMESTAMP_US, frame.len() as u32, frame.len() as u32)
        .expect_err("version 5 must fail");
    assert_eq!(err, DecodeError::UnsupportedIpVersion(5));
}

#[test]
fn truncated_transport_headers_are_reported_not_guessed() {
    // A frame whose IP header declares 40 bytes of payload but whose TCP header is cut
    // short is snaplen truncation, not corruption: the IP layer is still usable for flow
    // accounting, so the transport layer is left unset rather than guessed at.
    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.extend_from_slice(&fixtures::ipv4_header(
        6,
        40,
        0x4000,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    ));
    frame.extend_from_slice(&[0u8; 8]); // only 8 of the 20 TCP header bytes are present

    let original_len = frame.len() as u32 + 20; // the capture was cut short
    let packet = PacketDecoder::new()
        .decode(&frame, TIMESTAMP_US, frame.len() as u32, original_len)
        .expect("snaplen truncation is not a decode error");

    assert!(packet.ip.is_some(), "the IP header is still valid");
    assert!(packet.transport.is_none(), "no ports may be invented");
    assert!(packet.truncated, "a snaplen-cut frame is truncated");
    assert_eq!(packet.src_port(), None);
}

#[test]
fn unsupported_transport_protocol_keeps_the_ip_header() {
    let mut frame = fixtures::ethernet(ethertype::IPV4);
    frame.extend_from_slice(&fixtures::ipv4_header(
        47,
        28,
        0x4000,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    ));
    frame.extend_from_slice(&[0u8; 8]);

    let packet = PacketDecoder::new()
        .decode(&frame, TIMESTAMP_US, frame.len() as u32, frame.len() as u32)
        .expect("GRE is preserved, not an error");
    assert_eq!(packet.transport_protocol(), TransportProtocol::Other(47));
    assert!(packet.transport.is_none());
    assert!(
        packet.ip.is_some(),
        "the IP header is still useful for flow accounting"
    );
}

#[test]
fn decoding_is_deterministic_and_stateless() {
    let frame = fixtures::dns_query_frame(53_000, 0x1234, "example.com");
    let decoder = PacketDecoder::new();
    let first = decoder
        .decode(&frame, TIMESTAMP_US, frame.len() as u32, frame.len() as u32)
        .expect("decode");
    let second = decoder
        .decode(&frame, TIMESTAMP_US, frame.len() as u32, frame.len() as u32)
        .expect("decode");
    assert_eq!(
        first, second,
        "the decoder must hold no state between calls"
    );
}

#[test]
fn decode_error_message_is_non_alarming() {
    let err = DecodeError::Truncated {
        layer: "TCP",
        needed: 20,
        available: 4,
    };
    let message = sentinel_common::error::UserFacing::user_message(&err);
    assert!(message.summary.contains("counted this packet"));
    assert!(message.details.is_some());
}
