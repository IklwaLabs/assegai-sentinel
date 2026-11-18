//! Exposure findings: traffic that is dangerous by its nature rather than by its volume.
//!
//! Two rules live here because they share a property: neither is an inference about intent.
//! A Telnet connection *is* unencrypted, and a NULL-flag TCP packet *is* malformed. Sentinel
//! reports them because they are facts, with the caveat that the reason behind each may be
//! ordinary — an old device, a vendor's diagnostic tool, a scan the organisation asked for.

use sentinel_common::packet::NormalizedPacket;

use crate::finding::{Confidence, Evidence, FindingKind, Severity};
use crate::observation::Observation;
use crate::traffic::{connection_attempt, tcp};

/// A protocol that carries credentials or content without encryption.
struct Cleartext {
    port: u16,
    name: &'static str,
    severity: Severity,
    exposure: &'static str,
    replacement: &'static str,
}

/// The protocols Sentinel names, with what is exposed by each.
///
/// Ports are the only signal available without parsing payloads, and that is a real limitation:
/// a service on a non-standard port is missed, and a plaintext service on port 443 is missed.
/// The alternative — guessing from payload shape — would need to retain and inspect packet
/// contents, which this product deliberately does not do.
const CLEARTEXT: &[Cleartext] = &[
    Cleartext {
        port: 21,
        name: "FTP",
        severity: Severity::Medium,
        exposure: "file contents and, in the common case, the username and password",
        replacement: "SFTP or FTPS",
    },
    Cleartext {
        port: 23,
        name: "Telnet",
        severity: Severity::High,
        exposure: "the entire session, including the username and password",
        replacement: "SSH",
    },
    Cleartext {
        port: 25,
        name: "SMTP",
        severity: Severity::Low,
        exposure: "the contents of email sent through this server",
        replacement: "SMTP over TLS",
    },
    Cleartext {
        port: 69,
        name: "TFTP",
        severity: Severity::Medium,
        exposure: "whatever file is transferred, with no authentication at all",
        replacement: "SFTP or SCP",
    },
    Cleartext {
        port: 110,
        name: "POP3",
        severity: Severity::Medium,
        exposure: "the username, the password and the contents of the mailbox",
        replacement: "POP3S",
    },
    Cleartext {
        port: 143,
        name: "IMAP",
        severity: Severity::Medium,
        exposure: "the username, the password and the contents of the mailbox",
        replacement: "IMAPS",
    },
];

/// How many identities an exposure detector remembers before it clears its set.
///
/// The engine already deduplicates findings by identity, so forgetting costs only a repeated
/// observation that folds into the existing finding. An unbounded set here would let a flood
/// of spoofed sources exhaust memory before the engine's own cap ever applied.
const MAX_REMEMBERED: usize = 4_096;

/// Detects connections to protocols that do not encrypt.
#[derive(Debug, Default)]
pub struct CleartextDetector {
    /// Find the same connection once. Keyed by the same identity as the finding, so a retried
    /// SYN does not produce a second observation even though the engine would fold it into one.
    reported: std::collections::HashSet<String>,
}

impl CleartextDetector {
    /// Creates an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops all state, for a new capture session.
    pub fn reset(&mut self) {
        self.reported.clear();
    }

    /// Feeds one packet, returning a finding for a cleartext connection attempt.
    pub(crate) fn observe(&mut self, packet: &NormalizedPacket) -> Option<Observation> {
        let (source, destination, port) = connection_attempt(packet)?;
        let protocol = CLEARTEXT.iter().find(|entry| entry.port == port)?;
        let id = format!("cleartext|{source}|{destination}|{port}");
        if self.reported.len() >= MAX_REMEMBERED {
            self.reported.clear();
        }
        if !self.reported.insert(id.clone()) {
            return None;
        }

        Some(Observation {
            id,
            kind: FindingKind::CleartextProtocol,
            severity: protocol.severity,
            confidence: Confidence::High,
            title: format!("{} connection in the clear to {destination}", protocol.name),
            detail: format!(
                "{source} opened a {} connection to {destination}:{port}. {} sends {} without encryption, so anyone able to observe this path can read it.",
                protocol.name, protocol.name, protocol.exposure
            ),
            source: Some(source),
            destination: Some(destination),
            at_us: packet.timestamp_us,
            evidence: vec![
                Evidence::new("Protocol", protocol.name),
                Evidence::new("Port", port.to_string()),
                Evidence::new("Destination", destination.to_string()),
                Evidence::new("Encrypted alternative", protocol.replacement),
            ],
            advice: vec![
                "Check whether this connection is expected before treating it as a problem.",
                "Move the service to its encrypted equivalent where one exists.",
                "If credentials crossed this connection, change them: assume they were readable.",
            ],
        })
    }
}

/// Detects TCP header combinations that ordinary stacks do not emit.
///
/// These are the signatures of null, XMAS and SYN+FIN scans. They are reported as
/// [`Severity::Medium`] because the packet itself is unambiguous but its origin may be a
/// broken middlebox rather than an attacker; the advice says so.
#[derive(Debug, Default)]
pub struct TcpAnomalyDetector {
    reported: std::collections::HashSet<String>,
}

impl TcpAnomalyDetector {
    /// Creates an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops all state, for a new capture session.
    pub fn reset(&mut self) {
        self.reported.clear();
    }

    /// Feeds one packet, returning a finding for a malformed combination.
    pub(crate) fn observe(&mut self, packet: &NormalizedPacket) -> Option<Observation> {
        let header = tcp(packet)?;
        let flags = header.flags;

        let (kind, description, meaning) = if is_null(&flags) {
            (
                "null",
                "every TCP control bit is clear",
                "A packet with no control bits has no meaning in TCP; it is a probe designed to be answered differently by different operating systems.",
            )
        } else if flags.fin && flags.psh && flags.urg {
            (
                "xmas",
                "FIN, PSH and URG are all set",
                "The FIN, PSH and URG combination lights every bit a naive stack might look at, which is how an XMAS scan maps a host.",
            )
        } else if flags.syn && flags.fin {
            (
                "synFin",
                "SYN and FIN are both set",
                "A single segment cannot both open and close a connection, so this is a crafted probe rather than a real session.",
            )
        } else {
            return None;
        };

        let source = packet.src_ip()?;
        let destination = packet.dst_ip()?;
        let id = format!("tcpFlags|{kind}|{source}|{destination}");
        if self.reported.len() >= MAX_REMEMBERED {
            self.reported.clear();
        }
        if !self.reported.insert(id.clone()) {
            return None;
        }

        Some(Observation {
            id,
            kind: FindingKind::TcpFlagAnomaly,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Malformed TCP flags from {source}"),
            detail: format!(
                "{source} sent a TCP segment to {destination} in which {description}. {meaning}"
            ),
            source: Some(source),
            destination: Some(destination),
            at_us: packet.timestamp_us,
            evidence: vec![
                Evidence::new("Combination", description),
                Evidence::new("Destination", destination.to_string()),
                Evidence::new("Scan type", kind),
            ],
            advice: vec![
                "Identify the process on this host; scan tools and some vendor diagnostics emit these deliberately.",
                "If the host is not running a scan, treat it as compromised and investigate the rest of its traffic.",
                "Do not conclude from one packet alone: correlate with other findings from the same address.",
            ],
        })
    }
}

/// True when no TCP control bits are set.
fn is_null(flags: &sentinel_common::packet::TcpFlags) -> bool {
    !flags.fin
        && !flags.syn
        && !flags.rst
        && !flags.psh
        && !flags.ack
        && !flags.urg
        && !flags.ece
        && !flags.cwr
        && !flags.ns
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::packet::TcpFlags;

    use crate::testutil::{ack, syn, syn_ack, tcp_packet};

    const SRC: &str = "10.0.0.5";
    const DST: &str = "10.0.0.9";

    fn flags(fin: bool, syn: bool, psh: bool, urg: bool) -> TcpFlags {
        TcpFlags {
            fin,
            syn,
            rst: false,
            psh,
            ack: false,
            urg,
            ece: false,
            cwr: false,
            ns: false,
        }
    }

    #[test]
    fn ftp_in_the_clear_is_reported() {
        let mut detector = CleartextDetector::new();
        let finding = detector
            .observe(&tcp_packet(SRC, DST, 51_000, 21, syn(), 1))
            .expect("ftp");
        assert_eq!(finding.kind, FindingKind::CleartextProtocol);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.detail.contains("FTP"));
        assert!(finding.evidence.iter().any(|e| e.value == "21"));
    }

    #[test]
    fn telnet_is_high_severity_because_the_session_is_readable() {
        let mut detector = CleartextDetector::new();
        let finding = detector
            .observe(&tcp_packet(SRC, DST, 51_000, 23, syn(), 1))
            .expect("telnet");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn encrypted_traffic_is_not_reported() {
        let mut detector = CleartextDetector::new();
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 443, syn(), 1))
                .is_none()
        );
    }

    #[test]
    fn the_server_side_of_a_cleartext_connection_is_not_reported_twice() {
        let mut detector = CleartextDetector::new();
        assert!(
            detector
                .observe(&tcp_packet(DST, SRC, 21, 51_000, syn_ack(), 1))
                .is_none()
        );
    }

    #[test]
    fn a_cleartext_connection_is_reported_once_even_if_the_syn_retries() {
        let mut detector = CleartextDetector::new();
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 21, syn(), 1))
                .is_some()
        );
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 21, syn(), 2))
                .is_none()
        );
    }

    #[test]
    fn data_on_a_cleartext_port_is_not_a_new_connection() {
        let mut detector = CleartextDetector::new();
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 21, ack(), 1))
                .is_none()
        );
    }

    #[test]
    fn null_scan_is_reported() {
        let mut detector = TcpAnomalyDetector::new();
        let finding = detector
            .observe(&tcp_packet(
                SRC,
                DST,
                51_000,
                80,
                flags(false, false, false, false),
                1,
            ))
            .expect("null");
        assert_eq!(finding.kind, FindingKind::TcpFlagAnomaly);
        assert!(finding.detail.contains("every TCP control bit is clear"));
        assert!(finding.id.starts_with("tcpFlags|null|"));
    }

    #[test]
    fn xmas_scan_is_reported() {
        let mut detector = TcpAnomalyDetector::new();
        let finding = detector
            .observe(&tcp_packet(
                SRC,
                DST,
                51_000,
                80,
                flags(true, false, true, true),
                1,
            ))
            .expect("xmas");
        assert!(finding.id.starts_with("tcpFlags|xmas|"));
    }

    #[test]
    fn syn_fin_is_reported() {
        let mut detector = TcpAnomalyDetector::new();
        let finding = detector
            .observe(&tcp_packet(
                SRC,
                DST,
                51_000,
                80,
                flags(true, true, false, false),
                1,
            ))
            .expect("syn+fin");
        assert!(finding.id.starts_with("tcpFlags|synFin|"));
    }

    #[test]
    fn ordinary_tcp_is_not_reported() {
        let mut detector = TcpAnomalyDetector::new();
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 443, syn(), 1))
                .is_none()
        );
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 443, ack(), 2))
                .is_none()
        );
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 51_000, 443, syn_ack(), 3))
                .is_none()
        );
    }

    #[test]
    fn each_anomaly_form_has_its_own_identity() {
        let mut detector = TcpAnomalyDetector::new();
        let null = detector
            .observe(&tcp_packet(
                SRC,
                DST,
                1,
                80,
                flags(false, false, false, false),
                1,
            ))
            .expect("null");
        let xmas = detector
            .observe(&tcp_packet(
                SRC,
                DST,
                2,
                80,
                flags(true, false, true, true),
                2,
            ))
            .expect("xmas");
        assert_ne!(null.id, xmas.id);
    }

    #[test]
    fn a_repeated_anomaly_is_reported_once() {
        let mut detector = TcpAnomalyDetector::new();
        let flags = flags(false, false, false, false);
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 1, 80, flags, 1))
                .is_some()
        );
        assert!(
            detector
                .observe(&tcp_packet(SRC, DST, 2, 81, flags, 2))
                .is_none()
        );
    }

    #[test]
    fn the_cleartext_dedup_set_is_bounded() {
        // A flood of spoofed sources must not grow the detector without limit. Clearing the
        // set costs at most a repeated observation, which the engine folds into the finding.
        let mut detector = CleartextDetector::new();
        for index in 0..(MAX_REMEMBERED + 10) {
            let source = format!("10.1.{}.{}", index / 250, index % 250 + 1);
            detector.observe(&tcp_packet(
                &source,
                DST,
                51_000,
                23,
                syn(),
                1_000_000 + index as u64,
            ));
        }
        assert!(detector.reported.len() <= MAX_REMEMBERED);
    }

    #[test]
    fn the_tcp_anomaly_dedup_set_is_bounded() {
        let mut detector = TcpAnomalyDetector::new();
        let null = flags(false, false, false, false);
        for index in 0..(MAX_REMEMBERED + 10) {
            let source = format!("10.2.{}.{}", index / 250, index % 250 + 1);
            detector.observe(&tcp_packet(
                &source,
                DST,
                51_000,
                80,
                null,
                1_000_000 + index as u64,
            ));
        }
        assert!(detector.reported.len() <= MAX_REMEMBERED);
    }
}
