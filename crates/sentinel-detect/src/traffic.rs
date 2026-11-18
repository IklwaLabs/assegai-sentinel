//! Reading the few packet fields the detectors need.
//!
//! Every detector wants the same small facts — is this a connection attempt, who asked, who was
//! asked, which port — and each of them would otherwise re-derive those facts slightly
//! differently. That is how two detectors end up disagreeing about whether a packet was a SYN.
//!
//! So the extraction lives here once, with the exclusions that matter stated explicitly.

use std::net::IpAddr;

use sentinel_common::packet::{NormalizedPacket, TcpHeader, TransportHeader};

/// A packet that *asks* for a connection rather than answering one.
///
/// Returns the source, destination and destination port.
///
/// # Why SYN-without-ACK specifically
///
/// A SYN+ACK is the server answering, and counting it would make every connection look like
/// two attempts. A RST is a refusal, not an attempt. Filtering to the initial SYN is what makes
/// the port-scan and beacon counters measure the initiator, which is the party whose behaviour
/// is interesting.
#[must_use]
pub(crate) fn connection_attempt(packet: &NormalizedPacket) -> Option<(IpAddr, IpAddr, u16)> {
    let tcp = tcp(packet)?;
    if !tcp.flags.syn || tcp.flags.ack || tcp.flags.rst {
        return None;
    }
    Some((packet.src_ip()?, packet.dst_ip()?, tcp.destination_port))
}

/// The TCP header, when the packet carried TCP.
#[must_use]
pub(crate) fn tcp(packet: &NormalizedPacket) -> Option<TcpHeader> {
    match packet.transport? {
        TransportHeader::Tcp(header) => Some(header),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::packet::{IpHeader, Ipv4Header, TcpFlags};

    fn header(flags: TcpFlags) -> TcpHeader {
        TcpHeader {
            source_port: 51_000,
            destination_port: 443,
            sequence: 0,
            acknowledgement: 0,
            flags,
            window: 64_240,
            header_length: 20,
            option_count: 0,
            payload_length: 0,
        }
    }

    fn packet(flags: TcpFlags) -> NormalizedPacket {
        NormalizedPacket {
            timestamp_us: 1_000,
            captured_len: 40,
            original_len: 40,
            ethernet: None,
            vlan: None,
            arp: None,
            ip: Some(IpHeader::V4(Ipv4Header {
                source: [10, 0, 0, 5].into(),
                destination: [93, 184, 216, 34].into(),
                protocol: 6,
                ttl: 64,
                total_length: 40,
                dont_fragment: true,
                more_fragments: false,
                fragment_offset: 0,
                checksum: 0,
            })),
            transport: Some(TransportHeader::Tcp(header(flags))),
            payload_offset: 40,
            payload_len: 0,
            truncated: false,
            is_fragment: false,
        }
    }

    fn syn() -> TcpFlags {
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

    #[test]
    fn a_plain_syn_is_a_connection_attempt_with_its_addresses() {
        let attempt = connection_attempt(&packet(syn())).expect("attempt");
        assert_eq!(attempt.0.to_string(), "10.0.0.5");
        assert_eq!(attempt.1.to_string(), "93.184.216.34");
        assert_eq!(attempt.2, 443);
    }

    #[test]
    fn a_syn_ack_is_not_an_attempt_because_the_server_is_answering() {
        let mut flags = syn();
        flags.ack = true;
        assert!(connection_attempt(&packet(flags)).is_none());
    }

    #[test]
    fn a_reset_is_not_an_attempt() {
        let mut flags = syn();
        flags.rst = true;
        assert!(connection_attempt(&packet(flags)).is_none());
    }

    #[test]
    fn a_data_packet_is_not_an_attempt() {
        let mut flags = syn();
        flags.syn = false;
        flags.ack = true;
        assert!(connection_attempt(&packet(flags)).is_none());
        assert!(tcp(&packet(flags)).is_some());
    }

    #[test]
    fn a_packet_without_ip_or_tcp_yields_nothing_rather_than_guessing() {
        let mut empty = packet(syn());
        empty.ip = None;
        empty.transport = None;
        assert!(connection_attempt(&empty).is_none());
        assert!(tcp(&empty).is_none());

        empty.ip = packet(syn()).ip;
        assert!(connection_attempt(&empty).is_none(), "no TCP header");
    }
}
