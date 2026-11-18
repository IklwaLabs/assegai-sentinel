//! ARP deception, reported as a finding.
//!
//! The detection itself lives in `sentinel-response`, next to the repair that may follow it,
//! because the state machine that tells a spoof from a DHCP handoff is the same state machine
//! that must gate an automated correction. Duplicating it here would let the two disagree —
//! the detector calling something confirmed while the responder considered it unproven, or the
//! reverse.
//!
//! This module is therefore an adapter: it runs the monitor and turns a confirmed conflict into
//! a finding. It performs no I/O and sends nothing.

use sentinel_common::packet::NormalizedPacket;
use sentinel_response::{ArpMonitor, Verdict};

use crate::finding::{Confidence, Evidence, FindingKind, Severity};
use crate::observation::Observation;

/// Reports sustained ARP address conflicts.
#[derive(Debug, Default)]
pub struct DeceptionDetector {
    monitor: ArpMonitor,
}

impl DeceptionDetector {
    /// Creates an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            monitor: ArpMonitor::new(),
        }
    }

    /// Drops all state, for a new capture session.
    pub fn reset(&mut self) {
        self.monitor = ArpMonitor::new();
    }

    /// Feeds one packet, returning a finding when a conflict is sustained enough to report.
    pub(crate) fn observe(&mut self, packet: &NormalizedPacket) -> Option<Observation> {
        let arp = packet.arp.as_ref()?;
        match self.monitor.observe(arp) {
            Verdict::Report(conflict) => Some(observation(&conflict, packet.timestamp_us)),
            Verdict::NotYet { .. } => None,
        }
    }

    /// Number of addresses whose binding is being tracked.
    #[must_use]
    pub fn tracked_addresses(&self) -> usize {
        self.monitor.tracked()
    }
}

fn observation(conflict: &sentinel_response::ArpConflict, now_us: u64) -> Observation {
    let answering = if conflict.incumbent_still_answering {
        "The device that previously owned the address is still answering for it, so two machines are claiming one address."
    } else {
        "The previous owner has gone quiet and the new claimant is holding the address, which is also what a legitimate re-address looks like."
    };

    // The two outcomes are not equally certain. An incumbent that keeps answering while a
    // challenger also answers is an unambiguous conflict. A challenger that wins after the
    // incumbent goes silent is a takeover, but it is also what an ordinary hand-off looks like
    // once the old lease stops answering, so it is reported High/Medium rather than Critical.
    // If the incumbent later answers, the engine escalates the same finding to Critical.
    let (severity, confidence, title) = if conflict.incumbent_still_answering {
        (
            Severity::Critical,
            Confidence::High,
            format!("Two devices are claiming {}", conflict.ip),
        )
    } else {
        (
            Severity::High,
            Confidence::Medium,
            format!(
                "{} changed owner after the previous owner went silent",
                conflict.ip
            ),
        )
    };

    Observation {
        id: format!("arpSpoofing|{}", conflict.ip),
        kind: FindingKind::ArpSpoofing,
        severity,
        confidence,
        title,
        detail: format!(
            "{} belongs to {} and is now also being claimed by {}. {answering} Traffic intended for {} can be intercepted or redirected.",
            conflict.ip, conflict.incumbent_mac, conflict.challenger_mac, conflict.ip
        ),
        // The claiming device's IP is deliberately not guessed: the whole point of an ARP
        // spoof is that it is asserting an address it does not own, and the packet that
        // revealed it carries a MAC, not a trustworthy address. The MAC is the evidence.
        source: None,
        destination: Some(std::net::IpAddr::V4(conflict.ip)),
        at_us: now_us,
        evidence: vec![
            Evidence::new("Address", conflict.ip.to_string()),
            Evidence::new("Original owner", conflict.incumbent_mac.to_string()),
            Evidence::new("Claiming device", conflict.challenger_mac.to_string()),
            Evidence::new(
                "Original owner still answering",
                conflict.incumbent_still_answering.to_string(),
            ),
            Evidence::new("ARP messages observed", conflict.observations.to_string()),
        ],
        advice: vec![
            "Find the device with the claiming MAC address; it is the one intercepting traffic.",
            "Compare the default gateway's MAC against the address printed on the router.",
            "Isolate the claiming device, or correct the affected ARP cache by hand. This build does not send corrective frames.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::net::MacAddr;
    use sentinel_response::{ArpConflict, Confidence as ResponseConfidence};

    fn conflict(incumbent_still_answering: bool) -> ArpConflict {
        ArpConflict {
            ip: "192.168.1.1".parse().expect("valid"),
            incumbent_mac: MacAddr::from_bytes([0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc]),
            challenger_mac: MacAddr::from_bytes([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
            confidence: ResponseConfidence::Confirmed,
            observations: 4,
            incumbent_still_answering,
        }
    }

    #[test]
    fn an_incumbent_that_keeps_answering_is_a_critical_conflict() {
        let finding = observation(&conflict(true), 1_000);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, Confidence::High);
        assert!(finding.title.contains("Two devices"));
    }

    #[test]
    fn a_silent_handoff_is_reported_as_less_certain() {
        // The previous owner going quiet is also what a DHCP re-address looks like, so the
        // finding must not claim two devices are present or present itself as certain.
        let finding = observation(&conflict(false), 1_000);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert!(
            !finding.title.contains("Two devices"),
            "a silent handoff is one claimant, not two: {}",
            finding.title
        );
    }
}
