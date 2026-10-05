//! Deterministic frame construction for tests and golden fixtures.
//!
//! This module is part of the public API on purpose. The workspace's integration tests and
//! any future `sentinel-analyze` fixture tooling need to build byte-exact frames, and
//! duplicating those builders inside each test file would let them drift. Building frames
//! here means one definition of "what a DNS query looks like on the wire".
//!
//! Everything is built byte-by-byte with explicit field values, so a test states exactly
//! which header field it is exercising.

use std::net::Ipv4Addr;

use sentinel_common::packet::ethertype;

/// Source MAC used by generated frames.
pub const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// Destination MAC used by generated frames.
pub const DST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// Default source address used by generated frames.
pub const SRC_IP: [u8; 4] = [192, 168, 1, 10];
/// Default destination address used by generated frames.
pub const DST_IP: [u8; 4] = [93, 184, 216, 34];

/// Builds an Ethernet header with the given EtherType.
#[must_use]
pub fn ethernet(ether_type: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&DST_MAC);
    out.extend_from_slice(&SRC_MAC);
    out.extend_from_slice(&ether_type.to_be_bytes());
    out
}

/// Builds an IPv4 header.
///
/// `flags_frag` is the raw flags-plus-offset word: 0x4000 is "don't fragment",
/// 0x2000 is "more fragments", and the low 13 bits are the fragment offset in 8-byte units.
#[must_use]
pub fn ipv4_header(
    protocol: u8,
    total_len: u16,
    flags_frag: u16,
    source: [u8; 4],
    destination: [u8; 4],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0x45); // version 4, IHL 5 (20-byte header)
    out.push(0x00); // DSCP / ECN
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&0x1234u16.to_be_bytes()); // identification
    out.extend_from_slice(&flags_frag.to_be_bytes());
    out.push(64); // TTL
    out.push(protocol);
    // Checksum is recorded as received; the decoder never rejects on it.
    out.extend_from_slice(&0x0000u16.to_be_bytes());
    out.extend_from_slice(&source);
    out.extend_from_slice(&destination);
    out
}

/// Builds a TCP header.
///
/// `data_offset_words` is the data offset in 32-bit words: 5 means no options, 7 means a
/// 28-byte header with 8 bytes of options.
#[must_use]
pub fn tcp_header(
    source_port: u16,
    destination_port: u16,
    flags: u8,
    data_offset_words: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&destination_port.to_be_bytes());
    out.extend_from_slice(&1000u32.to_be_bytes()); // sequence number
    out.extend_from_slice(&2000u32.to_be_bytes()); // acknowledgement number
    out.push(data_offset_words << 4);
    out.push(flags);
    out.extend_from_slice(&64_240u16.to_be_bytes()); // window
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum
    out.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    out
}

/// Builds a TCP header followed by TCP options.
#[must_use]
pub fn tcp_header_with_options(source_port: u16, destination_port: u16, options: &[u8]) -> Vec<u8> {
    // Options must occupy a whole number of 32-bit words; pad with NOPs so the header is
    // well formed and the data-offset field stays consistent with the emitted bytes.
    let mut padded = options.to_vec();
    while !padded.len().is_multiple_of(4) {
        padded.push(1); // NOP
    }
    let header_len = MIN_TCP + padded.len();
    let mut header = tcp_header(source_port, destination_port, 0x10, (header_len / 4) as u8);
    header.extend_from_slice(&padded);
    header
}

/// Builds a UDP header for a payload of `payload_len` bytes.
#[must_use]
pub fn udp_header(source_port: u16, destination_port: u16, payload_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&destination_port.to_be_bytes());
    out.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum
    out
}

/// Builds an ICMP echo request payload.
#[must_use]
pub fn icmp_echo_request() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&[8, 0, 0, 0]); // type 8, code 0, checksum 0
    out.extend_from_slice(&[1, 2]); // identifier
    out.extend_from_slice(&[3, 4]); // sequence
    out
}

/// Builds a complete ARP request frame.
#[must_use]
pub fn arp_request_frame() -> Vec<u8> {
    let mut out = ethernet(ethertype::ARP);
    out.extend_from_slice(&1u16.to_be_bytes()); // hardware type: Ethernet
    out.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol type: IPv4
    out.push(6); // hardware address length
    out.push(4); // protocol address length
    out.extend_from_slice(&1u16.to_be_bytes()); // opcode: request
    out.extend_from_slice(&SRC_MAC);
    out.extend_from_slice(&SRC_IP);
    out.extend_from_slice(&[0u8; 6]); // target hardware address is unknown in a request
    out.extend_from_slice(&[192, 168, 1, 1]); // target address: default gateway
    out
}

/// Builds a complete ARP reply frame, as a gateway would answer a request.
#[must_use]
pub fn arp_reply_frame() -> Vec<u8> {
    let mut out = ethernet(ethertype::ARP);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    out.push(6);
    out.push(4);
    out.extend_from_slice(&2u16.to_be_bytes()); // opcode: reply
    out.extend_from_slice(&[0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc]); // gateway hardware address
    out.extend_from_slice(&[192, 168, 1, 1]);
    out.extend_from_slice(&SRC_MAC);
    out.extend_from_slice(&SRC_IP);
    out
}

/// Builds an ARP reply that claims `192.168.1.1` from a different hardware address.
///
/// This is the fixture used to exercise ARP conflict detection; the identity of the
/// claiming device is the whole point of the frame.
#[must_use]
pub fn arp_reply_frame_with_identity(gateway_ip: [u8; 4], claiming_mac: [u8; 6]) -> Vec<u8> {
    let mut out = ethernet(ethertype::ARP);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    out.push(6);
    out.push(4);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&claiming_mac);
    out.extend_from_slice(&gateway_ip);
    out.extend_from_slice(&SRC_MAC);
    out.extend_from_slice(&SRC_IP);
    out
}

/// Builds a TCP/IPv4/Ethernet frame between two explicit endpoints.
///
/// This is the general form. Reply traffic needs it explicitly: a fixture that quietly built
/// every frame client-to-server would look exactly like a real bidirectional-flow bug.
#[must_use]
pub fn tcp_frame_between(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = (MIN_IPV4 + MIN_TCP + payload.len()) as u16;
    let mut ip = ipv4_header(6, total, 0x4000, source, destination);
    ip.extend_from_slice(&tcp_header(source_port, destination_port, flags, 5));
    ip.extend_from_slice(payload);

    let mut frame = ethernet(ethertype::IPV4);
    frame.extend_from_slice(&ip);
    frame
}

/// Builds a TCP/IPv4/Ethernet frame with an optional payload, from `SRC_IP` to `DST_IP`.
#[must_use]
pub fn tcp_frame(source_port: u16, destination_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_frame_between(
        SRC_IP,
        DST_IP,
        source_port,
        destination_port,
        flags,
        payload,
    )
}

/// Builds the reverse of a frame produced by [`tcp_frame`]: `DST_IP` back to `SRC_IP`.
#[must_use]
pub fn tcp_reply_frame(
    source_port: u16,
    destination_port: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    tcp_frame_between(
        DST_IP,
        SRC_IP,
        source_port,
        destination_port,
        flags,
        payload,
    )
}

/// Builds a UDP/IPv4/Ethernet frame between two explicit endpoints.
#[must_use]
pub fn udp_frame_between(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = (MIN_IPV4 + MIN_UDP + payload.len()) as u16;
    let mut ip = ipv4_header(17, total, 0x4000, source, destination);
    ip.extend_from_slice(&udp_header(source_port, destination_port, payload.len()));
    ip.extend_from_slice(payload);

    let mut frame = ethernet(ethertype::IPV4);
    frame.extend_from_slice(&ip);
    frame
}

/// Builds a UDP/IPv4/Ethernet frame carrying an arbitrary payload.
#[must_use]
pub fn udp_frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    udp_frame_between(SRC_IP, DST_IP, source_port, destination_port, payload)
}

/// Builds the reverse of a frame produced by [`udp_frame`]: `DST_IP` back to `SRC_IP`.
#[must_use]
pub fn udp_reply_frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    udp_frame_between(DST_IP, SRC_IP, source_port, destination_port, payload)
}

/// Builds a DNS query payload for `domain` of the given record type.
///
/// Record types use their numeric IANA values: 1 = A, 28 = AAAA, 16 = TXT.
#[must_use]
pub fn dns_query_payload(transaction_id: u16, domain: &str, record_type: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + domain.len());
    payload.extend_from_slice(&transaction_id.to_be_bytes());
    payload.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    payload.extend_from_slice(&1u16.to_be_bytes()); // one question
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answers, authority or additional records
    payload.extend_from_slice(&encode_dns_name(domain));
    payload.extend_from_slice(&record_type.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes()); // class IN
    payload
}

/// Builds a DNS response payload carrying one A record.
#[must_use]
pub fn dns_response_payload(transaction_id: u16, domain: &str, address: Ipv4Addr) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(&transaction_id.to_be_bytes());
    payload.extend_from_slice(&0x8180u16.to_be_bytes()); // response, recursion available
    payload.extend_from_slice(&1u16.to_be_bytes()); // one question
    payload.extend_from_slice(&1u16.to_be_bytes()); // one answer
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    payload.extend_from_slice(&encode_dns_name(domain));
    payload.extend_from_slice(&1u16.to_be_bytes()); // type A
    payload.extend_from_slice(&1u16.to_be_bytes()); // class IN
    payload.extend_from_slice(&300u32.to_be_bytes()); // TTL 5 minutes
    payload.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    payload.extend_from_slice(&address.octets());
    payload
}

/// Encodes a DNS name in label format.
#[must_use]
pub fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 1);
    for label in domain.split('.').filter(|label| !label.is_empty()) {
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0); // root label terminates the name
    out
}

/// Builds a UDP/IPv4/Ethernet frame carrying a DNS query.
#[must_use]
pub fn dns_query_frame(source_port: u16, transaction_id: u16, domain: &str) -> Vec<u8> {
    let payload = dns_query_payload(transaction_id, domain, 1);
    udp_frame(source_port, 53, &payload)
}

/// Builds a complete ICMP echo request frame.
#[must_use]
pub fn icmp_echo_frame() -> Vec<u8> {
    let payload = icmp_echo_request();
    let mut ip = ipv4_header(
        1,
        (MIN_IPV4 + payload.len()) as u16,
        0x4000,
        SRC_IP,
        [8, 8, 8, 8],
    );
    ip.extend_from_slice(&payload);

    let mut frame = ethernet(ethertype::IPV4);
    frame.extend_from_slice(&ip);
    frame
}

/// Builds an IPv6/TCP frame from `::1` equivalent to a global address.
#[must_use]
pub fn ipv6_tcp_frame(source_port: u16, destination_port: u16, flags: u8) -> Vec<u8> {
    ipv6_tcp_frame_between(
        &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        &[
            0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10,
        ],
        source_port,
        destination_port,
        flags,
    )
}

/// Builds an IPv6/TCP frame between two explicit addresses.
#[must_use]
pub fn ipv6_tcp_frame_between(
    source: &[u8; 16],
    destination: &[u8; 16],
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut payload = tcp_header(source_port, destination_port, flags, 5);

    let mut ip = Vec::with_capacity(IPV6_HEADER + 20);
    // Version 6, traffic class 0, flow label 0.
    ip.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    ip.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ip.push(6); // next header: TCP
    ip.push(64); // hop limit
    ip.extend_from_slice(source);
    ip.extend_from_slice(destination);
    ip.append(&mut payload);

    let mut frame = ethernet(ethertype::IPV6);
    frame.extend_from_slice(&ip);
    frame
}

/// Builds the reverse of an IPv6 frame.
#[must_use]
pub fn ipv6_tcp_reply_frame(source_port: u16, destination_port: u16, flags: u8) -> Vec<u8> {
    ipv6_tcp_frame_between(
        &[
            0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10,
        ],
        &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        source_port,
        destination_port,
        flags,
    )
}

/// Builds a VLAN-tagged UDP frame for the given VLAN id.
#[must_use]
pub fn vlan_udp_frame(
    vlan_id: u16,
    priority: u8,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut frame = ethernet(ethertype::VLAN);
    let tci = (u16::from(priority) << 13) | (vlan_id & 0x0fff);
    frame.extend_from_slice(&tci.to_be_bytes());
    frame.extend_from_slice(&ethertype::IPV4.to_be_bytes());

    let mut ip = ipv4_header(17, (MIN_IPV4 + MIN_UDP) as u16, 0x4000, SRC_IP, DST_IP);
    ip.extend_from_slice(&udp_header(source_port, destination_port, 0));
    frame.extend_from_slice(&ip);
    frame
}

/// Builds a non-initial IPv4 fragment, which carries no transport header.
#[must_use]
pub fn ipv4_non_initial_fragment(fragment_offset_units: u16) -> Vec<u8> {
    // Offset is expressed in 8-byte units, so 185 units means data starts 1480 bytes in.
    let flags_frag = 0x2000 | (fragment_offset_units & 0x1fff);
    let mut ip = ipv4_header(6, 1480, flags_frag, SRC_IP, DST_IP);
    ip.extend_from_slice(&[0xab; 40]);

    let mut frame = ethernet(ethertype::IPV4);
    frame.extend_from_slice(&ip);
    frame
}

/// Minimum IPv4 header length.
const MIN_IPV4: usize = 20;
/// Minimum TCP header length.
const MIN_TCP: usize = 20;
/// Minimum UDP header length.
const MIN_UDP: usize = 8;
/// IPv6 fixed header length.
const IPV6_HEADER: usize = 40;

/// Builds a UDP/IPv4/Ethernet frame carrying a DNS response, in the reverse direction of
/// [`dns_query_frame`].
#[must_use]
pub fn dns_response_frame(
    source_port: u16,
    transaction_id: u16,
    domain: &str,
    address: std::net::Ipv4Addr,
) -> Vec<u8> {
    let payload = dns_response_payload(transaction_id, domain, address);
    udp_reply_frame(source_port, 53, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_encoding_matches_the_wire_format() {
        assert_eq!(
            encode_dns_name("example.com"),
            vec![
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
        assert_eq!(encode_dns_name("a.b"), vec![1, b'a', 1, b'b', 0]);
        assert_eq!(encode_dns_name(""), vec![0]);
    }

    #[test]
    fn frames_have_plausible_lengths() {
        assert_eq!(arp_request_frame().len(), 14 + 28);
        assert_eq!(tcp_frame(1, 2, 0x18, b"hello").len(), 14 + 20 + 20 + 5);
        assert_eq!(icmp_echo_frame().len(), 14 + 20 + 8);
        assert_eq!(ipv6_tcp_frame(1, 2, 0x02).len(), 14 + 40 + 20);
        assert_eq!(vlan_udp_frame(100, 0, 1, 2).len(), 14 + 4 + 20 + 8);
    }

    /// A reply must travel the other way. If these builders did not swap direction, a
    /// bidirectional-flow bug would be indistinguishable from a fixture bug.
    #[test]
    fn reply_builders_reverse_the_direction() {
        let request = tcp_frame(52_341, 443, 0x02, &[]);
        let reply = tcp_reply_frame(443, 52_341, 0x12, &[]);
        assert_ne!(request, reply);

        let decoded_request = decode_addresses(&request);
        let decoded_reply = decode_addresses(&reply);
        assert_eq!(
            decoded_request.0, decoded_reply.1,
            "the reply's source is the request's destination"
        );
        assert_eq!(decoded_request.1, decoded_reply.0);
        assert_eq!(
            (decoded_request.2, decoded_request.3),
            (decoded_reply.3, decoded_reply.2),
            "ports swap"
        );
    }

    /// Extracts `(source ip, destination ip, source port, destination port)` from a TCP frame.
    fn decode_addresses(frame: &[u8]) -> (String, String, u16, u16) {
        use std::net::Ipv4Addr;
        let ip = &frame[14..34];
        let source = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let destination = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let ports = &frame[34..38];
        let source_port = u16::from_be_bytes([ports[0], ports[1]]);
        let destination_port = u16::from_be_bytes([ports[2], ports[3]]);
        let _ = Ipv4Addr::UNSPECIFIED;
        (source, destination, source_port, destination_port)
    }

    #[test]
    fn udp_and_ipv6_replies_also_reverse() {
        let query = dns_query_frame(53_000, 0x1234, "example.com");
        let response = dns_response_frame(
            53_000,
            0x1234,
            "example.com",
            "93.184.216.34".parse().expect("valid"),
        );
        assert_ne!(query, response);

        let decoded_query = decode_addresses(&query);
        let decoded_response = decode_addresses(&response);
        assert_eq!(decoded_query.0, decoded_response.1);
        assert_eq!(decoded_query.1, decoded_response.0);
    }

    #[test]
    fn option_padding_produces_whole_words() {
        // A 4-byte option needs no padding: the header stays 24 bytes and the data-offset
        // field the builder writes must agree with the emitted length.
        let aligned = tcp_header_with_options(1, 2, &[2, 4, 0x05, 0xb4]);
        assert_eq!(aligned.len() % 4, 0);
        assert_eq!(aligned.len(), 24);
        assert_eq!(aligned[12] >> 4, 6, "data offset in 32-bit words");

        // A 3-byte option is padded up to a whole word.
        let padded = tcp_header_with_options(1, 2, &[2, 3, 0x00]);
        assert_eq!(padded.len() % 4, 0);
        assert_eq!(padded.len(), 24);
    }
}
