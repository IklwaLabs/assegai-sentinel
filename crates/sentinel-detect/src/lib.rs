//! Heuristic network detection for Iklwa Sentinel.
//!
//! # What this crate is for
//!
//! Until v0.2 Sentinel counted packets and tracked flows. That is instrumentation: it can tell
//! you a connection exists, not that anything is wrong. This crate is the decision layer — the
//! part that looks at traffic and says *this is worth your attention, and here is why*.
//!
//! # Design rules
//!
//! **Deterministic.** Time enters only as the packet's own timestamp. There is no clock, no
//! timer and no I/O, so every rule is testable by feeding packets in order and asserting on the
//! result. The tests are the specification.
//!
//! **Bounded.** All state is capped. A spoofed source address is free, and an attacker can send
//! from a million addresses precisely to turn a detector into a memory-exhaustion bug. Every
//! table here has a ceiling and a documented behaviour when it is reached.
//!
//! **Quiet by construction.** A finding is raised when a threshold is *crossed*, not on every
//! packet after it. One scan is one finding with a count, not twenty thousand alerts.
//!
//! **Honest about uncertainty.** Severity and confidence are separate, and every finding says
//! what was observed rather than what it means. [`Finding`] explains why.
//!
//! # What it does not do
//!
//! It does not inspect payloads — not even to look for a pattern. Sentinel's central privacy
//! promise is that packet contents are never retained, and a detector that peeked would make
//! that promise false. Everything here works from headers, timings and volumes.
//!
//! It also does not act. Detection runs whether or not response is enabled; see
//! `sentinel-response` for the separate, consent-gated part that can change the network.

#![forbid(unsafe_code)]

mod beacon;
mod deception;
mod exposure;
mod finding;
mod observation;
mod scan;
mod traffic;
mod volume;

#[cfg(test)]
mod testutil;

pub use beacon::BeaconDetector;
pub use deception::DeceptionDetector;
pub use exposure::{CleartextDetector, TcpAnomalyDetector};
pub use finding::{Confidence, Evidence, Finding, FindingKind, Severity};
pub use scan::ScanDetector;
pub use volume::VolumeDetector;

use std::collections::HashMap;

use sentinel_common::packet::NormalizedPacket;

use observation::Observation;

/// How many distinct findings are retained.
///
/// A cap is not a tidiness measure. Without one, traffic crafted to produce a new finding per
/// packet — a sweep from ever-changing addresses, say — would grow the list until the process
/// died. When the cap is reached, further findings are counted as suppressed rather than
/// silently dropped, so the interface can say that something was hidden instead of implying
/// the list is complete.
pub const MAX_FINDINGS: usize = 512;

/// The detection engine: every detector, plus the identity and retention rules that make their
/// output presentable.
#[derive(Debug, Default)]
pub struct DetectionEngine {
    scan: ScanDetector,
    beacon: BeaconDetector,
    volume: VolumeDetector,
    cleartext: CleartextDetector,
    tcp_anomalies: TcpAnomalyDetector,
    deception: DeceptionDetector,
    findings: Vec<Finding>,
    index: HashMap<String, usize>,
    suppressed: u64,
    observations: u64,
}

impl DetectionEngine {
    /// Creates an engine with no accumulated state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears all state for a new capture session.
    pub fn reset(&mut self) {
        self.scan.reset();
        self.beacon.reset();
        self.volume.reset();
        self.cleartext.reset();
        self.tcp_anomalies.reset();
        self.deception.reset();
        self.findings.clear();
        self.index.clear();
        self.suppressed = 0;
        self.observations = 0;
    }

    /// Feeds one decoded packet, returning findings that did not exist before this packet.
    ///
    /// Updates to an existing finding — its count, its latest evidence, its last-seen time —
    /// are applied in place and *not* returned. The caller already has the finding; returning
    /// it again on every packet would make a scan look like a stream of new events.
    pub fn observe(&mut self, packet: &NormalizedPacket) -> Vec<Finding> {
        self.observations = self.observations.saturating_add(1);

        // A small vector on the stack rather than an allocation per packet: in the common case
        // every detector returns `None` and nothing is allocated at all. The scan detector
        // contributes two slots because one frame can complete both a port scan and a sweep.
        let [scan, sweep] = self.scan.observe(packet);
        let mut observations: [Option<Observation>; 7] = [
            scan,
            sweep,
            self.beacon.observe(packet),
            self.volume.observe(packet),
            self.cleartext.observe(packet),
            self.tcp_anomalies.observe(packet),
            self.deception.observe(packet),
        ];

        let mut created = Vec::new();
        for observation in observations.iter_mut().filter_map(Option::take) {
            if let Some(finding) = self.absorb(observation) {
                created.push(finding);
            }
        }
        created
    }

    /// Folds one observation into the finding list.
    fn absorb(&mut self, observation: Observation) -> Option<Finding> {
        if let Some(&index) = self.index.get(&observation.id) {
            let finding = &mut self.findings[index];
            finding.last_seen_us = observation.at_us;
            finding.occurrences = finding.occurrences.saturating_add(1);
            // Escalate, never de-escalate: a finding that was once critical and is seen again
            // as merely suspicious is still the same critical finding.
            finding.severity = finding.severity.max(observation.severity);
            finding.confidence = finding.confidence.max(observation.confidence);
            // The latest detail and evidence are more informative than the first: they carry
            // the current counts rather than the state at the moment of discovery.
            finding.detail = observation.detail;
            finding.evidence = observation.evidence;
            if observation.destination.is_some() {
                finding.destination = observation.destination;
            }
            return None;
        }

        if self.findings.len() >= MAX_FINDINGS {
            self.suppressed = self.suppressed.saturating_add(1);
            tracing::warn!(
                id = %observation.id,
                "finding suppressed: the retention cap has been reached"
            );
            return None;
        }

        let advice = observation.advice_strings();
        let finding = Finding {
            id: observation.id,
            kind: observation.kind,
            severity: observation.severity,
            confidence: observation.confidence,
            title: observation.title,
            detail: observation.detail,
            source: observation.source,
            destination: observation.destination,
            first_seen_us: observation.at_us,
            last_seen_us: observation.at_us,
            occurrences: 1,
            evidence: observation.evidence,
            advice,
        };

        self.index.insert(finding.id.clone(), self.findings.len());
        self.findings.push(finding.clone());
        Some(finding)
    }

    /// Every finding raised so far, in the order they were first seen.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Findings ordered the way they should be shown, limited to `limit`.
    ///
    /// Sorts references and clones only the rows that survive the limit. The engine takes a
    /// snapshot several times a second, so cloning the whole list on every tick would allocate
    /// on a timer.
    #[must_use]
    pub fn findings_for_display(&self, limit: usize) -> Vec<Finding> {
        let mut ordered: Vec<&Finding> = self.findings.iter().collect();
        ordered.sort_by(|a, b| Finding::display_order(a, b));
        ordered.into_iter().take(limit).cloned().collect()
    }

    /// How many distinct findings are held.
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// How many finding observations were dropped because the cap was reached.
    ///
    /// Counted per observation rather than per identity, because remembering every suppressed
    /// identity would reintroduce the unbounded growth the cap exists to prevent.
    #[must_use]
    pub fn suppressed(&self) -> u64 {
        self.suppressed
    }

    /// How many packets have been inspected.
    #[must_use]
    pub fn observations(&self) -> u64 {
        self.observations
    }
}

/// A one-line summary of a finding list, for logs and the status bar.
#[must_use]
pub fn summarise(findings: &[Finding]) -> String {
    let total = findings.len();
    if total == 0 {
        return "no findings".to_string();
    }

    let critical = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|finding| finding.severity == Severity::High)
        .count();
    let noun = if total == 1 { "finding" } else { "findings" };

    match (critical, high) {
        (0, 0) => format!("{total} {noun}"),
        (0, high) => format!("{total} {noun}, {high} high"),
        (critical, high) => format!("{total} {noun}, {critical} critical, {high} high"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{arp_packet, arp_reply, syn, syn_ack, tcp_packet};

    const SRC: &str = "10.0.0.5";
    const DST: &str = "10.0.0.9";

    #[test]
    fn a_fresh_engine_reports_nothing() {
        let engine = DetectionEngine::new();
        assert_eq!(engine.finding_count(), 0);
        assert_eq!(engine.suppressed(), 0);
        assert_eq!(summarise(engine.findings()), "no findings");
    }

    #[test]
    fn ordinary_traffic_produces_no_findings() {
        let mut engine = DetectionEngine::new();
        for index in 0..1_000u64 {
            let packet = tcp_packet(SRC, DST, 51_000, 443, syn(), 1_000_000 + index * 1_000);
            assert!(engine.observe(&packet).is_empty());
        }
        assert_eq!(engine.finding_count(), 0);
    }

    #[test]
    fn a_scan_is_one_finding_with_a_count_not_one_finding_per_packet() {
        let mut engine = DetectionEngine::new();
        let mut created = Vec::new();
        for offset in 0..40u16 {
            let packet = tcp_packet(
                SRC,
                DST,
                40_000 + offset,
                // High ports on purpose: 21, 23 and 25 are cleartext protocols and would
                // (correctly) produce their own findings, which is a different test.
                5_000 + offset,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            );
            created.extend(engine.observe(&packet));
        }

        assert_eq!(engine.finding_count(), 1);
        assert_eq!(
            created.len(),
            1,
            "only the finding that was created is returned"
        );
        let finding = &engine.findings()[0];
        assert_eq!(finding.occurrences, 1);
        assert_eq!(finding.kind, FindingKind::PortScan);
    }

    #[test]
    fn severity_and_confidence_only_escalate_on_repeat_observations() {
        // Direct test of the fold, because a rule that can de-escalate would let a second,
        // quieter observation of the same behaviour bury the first.
        let mut engine = DetectionEngine::new();
        let high = Observation {
            id: "test".to_string(),
            kind: FindingKind::PortScan,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "first".to_string(),
            detail: "first".to_string(),
            source: None,
            destination: None,
            at_us: 10,
            evidence: Vec::new(),
            advice: Vec::new(),
        };
        engine.absorb(high);

        let quiet = Observation {
            id: "test".to_string(),
            kind: FindingKind::PortScan,
            severity: Severity::Low,
            confidence: Confidence::Low,
            title: "second".to_string(),
            detail: "second".to_string(),
            source: None,
            destination: None,
            at_us: 20,
            evidence: Vec::new(),
            advice: Vec::new(),
        };
        assert!(engine.absorb(quiet).is_none());

        let finding = &engine.findings()[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.occurrences, 2);
        assert_eq!(finding.last_seen_us, 20);
        assert_eq!(finding.detail, "second");
    }

    #[test]
    fn a_confirmed_arp_conflict_becomes_a_critical_finding() {
        let mut engine = DetectionEngine::new();
        let gateway = "192.168.1.1";
        let owner = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let attacker = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

        // Incumbent, then challenger, then the incumbent answering after the challenger:
        // the sequence that distinguishes a spoof from a re-address.
        let mut created = Vec::new();
        created.extend(engine.observe(&arp_packet(
            arp_reply(owner, gateway, [0; 6], "192.168.1.50"),
            1,
        )));
        created.extend(engine.observe(&arp_packet(
            arp_reply(attacker, gateway, [0; 6], "192.168.1.50"),
            2,
        )));
        created.extend(engine.observe(&arp_packet(
            arp_reply(owner, gateway, [0; 6], "192.168.1.50"),
            3,
        )));

        let finding = created.first().expect("arp finding");
        assert_eq!(finding.kind, FindingKind::ArpSpoofing);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(
            finding.destination,
            Some("192.168.1.1".parse().expect("valid"))
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|e| e.label == "Claiming device")
        );
    }

    #[test]
    fn one_confirmation_of_a_new_address_is_not_a_finding() {
        // The false-positive guard, asserted at the engine boundary rather than only inside the
        // detector, because the two must agree about what reaches the interface.
        let mut engine = DetectionEngine::new();
        let owner = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let newcomer = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let gateway = "192.168.1.1";

        engine.observe(&arp_packet(
            arp_reply(owner, gateway, [0; 6], "192.168.1.50"),
            1,
        ));
        engine.observe(&arp_packet(
            arp_reply(newcomer, gateway, [0; 6], "192.168.1.50"),
            2,
        ));
        assert_eq!(
            engine.finding_count(),
            0,
            "a DHCP re-address is not an attack"
        );
    }

    #[test]
    fn a_non_arp_packet_does_not_disturb_the_arp_monitor() {
        let mut engine = DetectionEngine::new();
        for index in 0..10u64 {
            engine.observe(&tcp_packet(SRC, DST, 51_000, 443, syn_ack(), index));
        }
        assert_eq!(engine.finding_count(), 0);
    }

    #[test]
    fn reset_clears_findings_and_all_detector_state() {
        let mut engine = DetectionEngine::new();
        for offset in 0..scan::VERTICAL_PORTS {
            engine.observe(&tcp_packet(
                SRC,
                DST,
                40_000 + offset as u16,
                1 + offset as u16,
                syn(),
                1_000_000 + offset as u64 * 1_000,
            ));
        }
        assert_eq!(
            engine.finding_count(),
            1,
            "the scan should be visible first"
        );
        engine.reset();
        assert_eq!(engine.finding_count(), 0);
        assert_eq!(engine.observations(), 0);
    }

    #[test]
    fn the_display_order_is_most_severe_first() {
        let mut engine = DetectionEngine::new();
        engine.absorb(Observation {
            id: "a".to_string(),
            kind: FindingKind::PortScan,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "low".to_string(),
            detail: String::new(),
            source: None,
            destination: None,
            at_us: 100,
            evidence: Vec::new(),
            advice: Vec::new(),
        });
        engine.absorb(Observation {
            id: "b".to_string(),
            kind: FindingKind::ArpSpoofing,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "critical".to_string(),
            detail: String::new(),
            source: None,
            destination: None,
            at_us: 50,
            evidence: Vec::new(),
            advice: Vec::new(),
        });
        let ordered = engine.findings_for_display(10);
        assert_eq!(ordered[0].severity, Severity::Critical);
        assert_eq!(ordered[1].severity, Severity::Low);

        let limited = engine.findings_for_display(1);
        assert_eq!(
            limited.len(),
            1,
            "the limit must bound the clone, not just the view"
        );
        assert_eq!(limited[0].severity, Severity::Critical);
    }

    #[test]
    fn the_retention_cap_holds_and_suppression_is_visible() {
        let mut engine = DetectionEngine::new();
        let owner = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let attacker = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

        // One sustained ARP conflict per gateway address produces one distinct finding. Using
        // ARP rather than scans keeps this test about the finding cap, not about how many
        // windows the scan detector may hold.
        let mut timestamp = 1u64;
        for host in 0..(MAX_FINDINGS as u32 + 5) {
            let gateway = format!("192.168.{}.{}", host / 200, host % 200 + 1);
            for sender in [owner, attacker, owner] {
                timestamp += 1;
                engine.observe(&arp_packet(
                    arp_reply(sender, &gateway, [0; 6], "192.168.1.50"),
                    timestamp,
                ));
            }
        }

        assert_eq!(engine.finding_count(), MAX_FINDINGS);
        assert!(
            engine.suppressed() > 0,
            "findings beyond the cap must be counted, not silently dropped"
        );
    }

    #[test]
    fn the_summary_counts_the_severities_that_matter() {
        let make = |severity| Finding {
            id: String::new(),
            kind: FindingKind::PortScan,
            severity,
            confidence: Confidence::High,
            title: String::new(),
            detail: String::new(),
            source: None,
            destination: None,
            first_seen_us: 0,
            last_seen_us: 0,
            occurrences: 1,
            evidence: Vec::new(),
            advice: Vec::new(),
        };
        assert_eq!(
            summarise(&[
                make(Severity::Critical),
                make(Severity::High),
                make(Severity::Low)
            ]),
            "3 findings, 1 critical, 1 high"
        );
        assert_eq!(summarise(&[make(Severity::Low)]), "1 finding");
    }
}
