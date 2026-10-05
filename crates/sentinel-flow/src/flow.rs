//! The flow record and its state machine.

use std::collections::BTreeSet;
use std::net::IpAddr;

use sentinel_common::clock;
use sentinel_common::packet::{NormalizedPacket, TcpFlags, TransportHeader, TransportProtocol};
use serde::{Deserialize, Serialize};

use crate::key::{Endpoint, FlowKey, FlowSide};

/// Observable connection state, derived from observed TCP control bits.
///
/// This is deliberately a *derived* state, not a full state machine. Sentinel never sends
/// packets, so it cannot assert what a connection "is" — only what the observed traffic is
/// consistent with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FlowState {
    /// Nothing conclusive observed yet.
    #[default]
    Unknown,
    /// A SYN was seen in at least one direction.
    SynSent,
    /// A SYN and an ACK were both seen: the handshake completed.
    Established,
    /// A FIN or RST was seen.
    Closed,
}

impl FlowState {
    /// Label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            FlowState::Unknown => "Observed",
            FlowState::SynSent => "Connecting",
            FlowState::Established => "Active",
            FlowState::Closed => "Closed",
        }
    }

    /// Applies observed TCP flags to the state.
    ///
    /// Transitions are monotonic toward "more established", except RST which is decisive.
    /// A late packet on an established connection must not downgrade it back to connecting.
    fn observe(&mut self, flags: TcpFlags) {
        if flags.rst {
            *self = FlowState::Closed;
            return;
        }
        if flags.fin {
            *self = FlowState::Closed;
            return;
        }
        match self {
            FlowState::Closed | FlowState::Established => {}
            FlowState::Unknown => {
                if flags.syn {
                    *self = FlowState::SynSent;
                }
            }
            FlowState::SynSent => {
                if flags.ack {
                    *self = FlowState::Established;
                }
            }
        }
    }
}

/// Process attribution for a flow.
///
/// Filled in by the process resolver where the operating system allows it. `None` means
/// "not resolved", which is a normal outcome on some platforms and privilege levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRef {
    /// Process identifier.
    pub pid: u32,
    /// Executable file name, e.g. `chrome.exe`.
    pub name: String,
    /// Full executable path when the OS exposes it.
    #[serde(default)]
    pub path: Option<String>,
    /// User-friendly product name when identifiable.
    #[serde(default)]
    pub application: Option<String>,
}

/// A tracked bidirectional connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Flow {
    /// Normalized key identifying the connection.
    pub key: FlowKey,
    /// Observed connection state.
    pub state: FlowState,
    /// First packet timestamp in microseconds since the Unix epoch.
    pub first_seen_us: u64,
    /// Most recent packet timestamp in microseconds since the Unix epoch.
    pub last_seen_us: u64,
    /// Bytes sent by `initiator`.
    pub bytes_sent: u64,
    /// Bytes received by `initiator`.
    pub bytes_received: u64,
    /// Packets sent by `initiator`.
    pub packets_sent: u64,
    /// Packets received by `initiator`.
    pub packets_received: u64,
    /// Application-layer service inferred from the port, e.g. "DNS".
    #[serde(default)]
    pub service: Option<String>,
    /// Resolved domain name for this connection, when known.
    #[serde(default)]
    pub domain: Option<String>,
    /// Process attribution, when resolvable.
    #[serde(default)]
    pub process: Option<ProcessRef>,
    /// Risk score in `0..=100`, assigned by the risk engine.
    #[serde(default)]
    pub risk_score: Option<u8>,
    /// Number of alerts attributed to this flow.
    #[serde(default)]
    pub alert_count: u32,
    /// Free-form labels for grouping and filtering.
    #[serde(default)]
    pub tags: BTreeSet<String>,
    /// Which side initiated the connection, when the ports identify it.
    #[serde(default)]
    pub initiator: Option<FlowSide>,
}

impl Flow {
    /// Creates an empty flow for a newly observed key.
    #[must_use]
    pub fn new(key: FlowKey, timestamp_us: u64) -> Self {
        Self {
            key,
            state: FlowState::Unknown,
            first_seen_us: timestamp_us,
            last_seen_us: timestamp_us,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            service: None,
            domain: None,
            process: None,
            risk_score: None,
            alert_count: 0,
            tags: BTreeSet::new(),
            initiator: key.likely_initiator(),
        }
    }

    /// Total bytes in both directions.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    /// Total packets in both directions.
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }

    /// Connection duration in microseconds.
    #[must_use]
    pub const fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }

    /// Average throughput in bits per second over the flow's lifetime.
    ///
    /// Returns `0.0` for a zero-length flow rather than dividing by zero. Flows younger
    /// than one second use one second as the denominator, because a flow observed for 200 ms
    /// does not carry 200 ms of a meaningful average.
    #[must_use]
    pub fn average_bps(&self) -> f64 {
        let duration_us = self.duration_us().max(1_000_000);
        f64::from((self.total_bytes() * 8) as u32) * 1_000_000.0 / duration_us as f64
    }

    /// The endpoint that initiated the connection, when identified.
    #[must_use]
    pub fn initiator_endpoint(&self) -> Option<Endpoint> {
        match self.initiator? {
            FlowSide::A => Some(self.key.endpoint_a),
            FlowSide::B => Some(self.key.endpoint_b),
        }
    }

    /// The remote endpoint relative to a local address.
    #[must_use]
    pub fn remote_from(&self, local: IpAddr) -> Option<Endpoint> {
        match self.key.side_of(local) {
            Some(FlowSide::A) => Some(self.key.endpoint_b),
            Some(FlowSide::B) => Some(self.key.endpoint_a),
            None => None,
        }
    }

    /// Applies one packet to the flow, attributing bytes to the correct direction.
    ///
    /// `sent` is true when the packet travelled from the initiator to the other side.
    pub(crate) fn apply_packet(
        &mut self,
        packet: &NormalizedPacket,
        sent_by_initiator: bool,
        wire_len: u64,
    ) {
        self.last_seen_us = packet.timestamp_us;

        if sent_by_initiator {
            self.bytes_sent = self.bytes_sent.saturating_add(wire_len);
            self.packets_sent = self.packets_sent.saturating_add(1);
        } else {
            self.bytes_received = self.bytes_received.saturating_add(wire_len);
            self.packets_received = self.packets_received.saturating_add(1);
        }

        if let Some(TransportHeader::Tcp(tcp)) = packet.transport {
            self.state.observe(tcp.flags);
        } else if self.state == FlowState::Unknown
            && matches!(packet.transport_protocol(), TransportProtocol::Udp)
        {
            // UDP has no handshake, so observing it is the only evidence of activity.
            self.state = FlowState::Established;
        }
    }

    /// Fills in a service name from the port when it is still unknown.
    pub(crate) fn infer_service(&mut self) {
        if self.service.is_some() {
            return;
        }
        let protocol = self.key.protocol;
        if !protocol.has_ports() {
            return;
        }
        // Check both sides: a flow can be server-side or client-side.
        for endpoint in [self.key.endpoint_a, self.key.endpoint_b] {
            if let Some(name) = service_for_port(endpoint.port.unwrap_or_default()) {
                self.service = Some(name.to_string());
                return;
            }
        }
    }
}

/// Result of applying a packet to the flow table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowUpdate {
    /// A new flow was created.
    Created,
    /// An existing flow was updated.
    Updated,
    /// The packet carried no flow identity (for example ARP or a non-IP fragment).
    Ignored,
}

impl FlowUpdate {
    /// True when this update created a new flow.
    #[must_use]
    pub const fn is_created(self) -> bool {
        matches!(self, FlowUpdate::Created)
    }
}

/// Maps a port number to a well-known service name.
///
/// Only unambiguous, widely used ports are mapped. Guessing service names from uncommon
/// ports would show users wrong information.
fn service_for_port(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        69 => Some("TFTP"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        123 => Some("NTP"),
        137..=139 => Some("NetBIOS"),
        143 => Some("IMAP"),
        161 | 162 => Some("SNMP"),
        389 => Some("LDAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        514 => Some("Syslog"),
        587 => Some("Submission"),
        631 => Some("IPP"),
        636 => Some("LDAPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1194 => Some("OpenVPN"),
        1701 => Some("L2TP"),
        1900 => Some("SSDP"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5353 => Some("mDNS"),
        5060 => Some("SIP"),
        51820 => Some("WireGuard"),
        3478 => Some("STUN"),
        5222 => Some("XMPP"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        _ => None,
    }
}

/// Formats a timestamp for display in a flow row.
#[must_use]
pub fn format_timestamp(timestamp_us: u64) -> String {
    clock::unix_micros_to_clock(timestamp_us)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use sentinel_common::packet::{
        EthernetFrame, IpHeader, Ipv4Header, TcpHeader, TransportHeader, TransportProtocol,
        UdpHeader,
    };

    fn key() -> FlowKey {
        FlowKey::new(
            TransportProtocol::Tcp,
            Endpoint::new("192.168.1.10".parse().expect("valid"), Some(52_341)),
            Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
        )
    }

    fn tcp_packet(
        timestamp_us: u64,
        flags: TcpFlags,
        from_client: bool,
        wire_len: u64,
    ) -> NormalizedPacket {
        let (src, dst, src_port, dst_port) = if from_client {
            ("192.168.1.10", "93.184.216.34", 52_341u16, 443u16)
        } else {
            ("93.184.216.34", "192.168.1.10", 443, 52_341)
        };

        NormalizedPacket {
            timestamp_us,
            captured_len: 60,
            original_len: wire_len as u32,
            ethernet: Some(EthernetFrame {
                destination: Default::default(),
                source: Default::default(),
                ethertype: 0x0800,
            }),
            vlan: None,
            arp: None,
            ip: Some(IpHeader::V4(Ipv4Header {
                source: src.parse().expect("valid source"),
                destination: dst.parse().expect("valid destination"),
                protocol: 6,
                ttl: 64,
                total_length: 40,
                dont_fragment: true,
                more_fragments: false,
                fragment_offset: 0,
                checksum: 0,
            })),
            transport: Some(TransportHeader::Tcp(TcpHeader {
                source_port: src_port,
                destination_port: dst_port,
                sequence: 0,
                acknowledgement: 0,
                flags,
                window: 0,
                header_length: 20,
                option_count: 0,
                payload_length: 0,
            })),
            payload_offset: 54,
            payload_len: 0,
            truncated: false,
            is_fragment: false,
        }
    }

    #[test]
    fn counters_split_by_direction_relative_to_the_initiator() {
        // The table constructs a flow with the first packet's timestamp, which is what
        // establishes `first_seen_us`.
        let mut flow = Flow::new(key(), 1_000);
        // Canonical ordering makes the server (93.184.216.34:443) side A, so the client on
        // the ephemeral port is side B and is the initiator.
        assert_eq!(
            flow.initiator,
            Some(FlowSide::B),
            "the ephemeral client is the initiator"
        );

        let client_packet = tcp_packet(
            1_000,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            true,
            60,
        );
        let server_packet = tcp_packet(
            2_000,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            false,
            74,
        );

        // Direction is decided by mapping the packet's source address onto the key's sides.
        let flow_key = key();
        let initiator = flow.initiator.expect("initiator identified");
        let from_initiator = |packet: &NormalizedPacket| {
            flow_key.side_of(packet.src_ip().expect("source address")) == Some(initiator)
        };
        assert!(from_initiator(&client_packet));
        assert!(!from_initiator(&server_packet));

        flow.apply_packet(&client_packet, from_initiator(&client_packet), 60);
        flow.apply_packet(&server_packet, from_initiator(&server_packet), 74);

        assert_eq!(flow.packets_sent, 1, "one packet from the initiator");
        assert_eq!(flow.bytes_sent, 60);
        assert_eq!(flow.packets_received, 1);
        assert_eq!(flow.bytes_received, 74);
        assert_eq!(flow.total_packets(), 2);
        assert_eq!(flow.total_bytes(), 134);
        assert_eq!(flow.first_seen_us, 1_000);
        assert_eq!(flow.last_seen_us, 2_000);
        assert_eq!(flow.duration_us(), 1_000);
    }

    #[test]
    fn tcp_state_progresses_and_does_not_regress() {
        let mut flow = Flow::new(key(), 0);

        flow.apply_packet(
            &tcp_packet(
                0,
                TcpFlags {
                    syn: true,
                    ..Default::default()
                },
                true,
                60,
            ),
            true,
            60,
        );
        assert_eq!(flow.state, FlowState::SynSent);

        flow.apply_packet(
            &tcp_packet(
                1,
                TcpFlags {
                    syn: true,
                    ack: true,
                    ..Default::default()
                },
                false,
                60,
            ),
            false,
            60,
        );
        assert_eq!(flow.state, FlowState::Established);

        // A later packet without SYN must not downgrade the connection.
        flow.apply_packet(
            &tcp_packet(
                2,
                TcpFlags {
                    ack: true,
                    psh: true,
                    ..Default::default()
                },
                true,
                100,
            ),
            true,
            100,
        );
        assert_eq!(flow.state, FlowState::Established);

        flow.apply_packet(
            &tcp_packet(
                3,
                TcpFlags {
                    rst: true,
                    ..Default::default()
                },
                false,
                54,
            ),
            false,
            54,
        );
        assert_eq!(flow.state, FlowState::Closed, "RST is decisive");
    }

    #[test]
    fn fin_closes_a_flow() {
        let mut flow = Flow::new(key(), 0);
        flow.state = FlowState::Established;
        flow.apply_packet(
            &tcp_packet(
                0,
                TcpFlags {
                    fin: true,
                    ack: true,
                    ..Default::default()
                },
                true,
                54,
            ),
            true,
            54,
        );
        assert_eq!(flow.state, FlowState::Closed);
    }

    /// An empty packet with no layers set, so tests can fill in only what they exercise.
    fn empty_packet() -> NormalizedPacket {
        NormalizedPacket {
            timestamp_us: 0,
            captured_len: 0,
            original_len: 0,
            ethernet: None,
            vlan: None,
            arp: None,
            ip: None,
            transport: None,
            payload_offset: 0,
            payload_len: 0,
            truncated: false,
            is_fragment: false,
        }
    }

    #[test]
    fn udp_is_observed_as_established_immediately() {
        let key = FlowKey::new(
            TransportProtocol::Udp,
            Endpoint::new("10.0.0.1".parse().expect("valid"), Some(53_000)),
            Endpoint::new("10.0.0.2".parse().expect("valid"), Some(53)),
        );
        let mut flow = Flow::new(key, 0);
        let packet = NormalizedPacket {
            ip: Some(IpHeader::V4(Ipv4Header {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                protocol: 17,
                ttl: 64,
                total_length: 40,
                dont_fragment: true,
                more_fragments: false,
                fragment_offset: 0,
                checksum: 0,
            })),
            transport: Some(TransportHeader::Udp(UdpHeader {
                source_port: 53_000,
                destination_port: 53,
                length: 28,
            })),
            ..empty_packet()
        };
        flow.apply_packet(&packet, true, 40);
        assert_eq!(flow.state, FlowState::Established);
    }

    #[test]
    fn service_is_inferred_from_a_known_port() {
        let mut flow = Flow::new(key(), 0);
        assert_eq!(flow.service, None);
        flow.infer_service();
        assert_eq!(flow.service.as_deref(), Some("HTTPS"));

        // An already-resolved service is never overwritten.
        flow.infer_service();
        assert_eq!(flow.service.as_deref(), Some("HTTPS"));
    }

    #[test]
    fn uncommon_ports_do_not_get_a_guessed_service() {
        let odd = FlowKey::new(
            TransportProtocol::Tcp,
            Endpoint::new("10.0.0.1".parse().expect("valid"), Some(51_234)),
            Endpoint::new("10.0.0.2".parse().expect("valid"), Some(51_235)),
        );
        let mut flow = Flow::new(odd, 0);
        flow.infer_service();
        assert_eq!(
            flow.service, None,
            "uncommon ports must not be labelled with a guess"
        );
    }

    #[test]
    fn throughput_uses_a_one_second_floor() {
        let mut flow = Flow::new(key(), 0);
        assert_eq!(
            flow.average_bps(),
            0.0,
            "zero-length flow must not divide by zero"
        );

        flow.bytes_sent = 1_000_000; // 1 MB
        flow.last_seen_us = 500_000; // half a second
        let bps = flow.average_bps();
        assert_eq!(
            bps, 8_000_000.0,
            "1 MB in under a second reports as 8 Mbps, not 16"
        );
    }

    #[test]
    fn remote_endpoint_is_resolved_from_the_local_address() {
        let flow = Flow::new(key(), 0);
        let local: IpAddr = "192.168.1.10".parse().expect("valid");
        assert_eq!(
            flow.remote_from(local).map(|e| e.display()).as_deref(),
            Some("93.184.216.34:443")
        );

        let foreign: IpAddr = "8.8.8.8".parse().expect("valid");
        assert_eq!(flow.remote_from(foreign), None);
    }

    #[test]
    fn flow_update_reports_creation() {
        assert!(FlowUpdate::Created.is_created());
        assert!(!FlowUpdate::Updated.is_created());
        assert!(!FlowUpdate::Ignored.is_created());
    }
}
