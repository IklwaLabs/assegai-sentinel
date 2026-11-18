//! Large one-directional uploads to the internet.
//!
//! # What this catches, and what it misses
//!
//! Exfiltration usually has a shape: a large volume leaving the machine, with little or nothing
//! coming back. A backup, a software update or a file sync has the opposite shape — data leaving
//! is matched by data arriving, or the upload is a known, steady rate.
//!
//! So the rule is volume *and* asymmetry inside a short window. Either alone produces false
//! alarms constantly: video calls upload a lot, and a database replica receives a lot.
//!
//! # The honest limit
//!
//! This catches a burst. It does not catch a slow drip designed to stay under any fixed
//! threshold, because doing that properly needs a learned baseline per host and per time of day.
//! Sentinel does not have one yet, and a threshold pretending to be a baseline would be worse
//! than a threshold that says what it is.

use std::collections::HashMap;
use std::net::IpAddr;

use sentinel_common::net::is_private_addr;
use sentinel_common::packet::NormalizedPacket;

use crate::finding::{Confidence, Evidence, FindingKind, Severity};
use crate::observation::Observation;

/// How long an upload burst is measured over.
const WINDOW_US: u64 = 60_000_000;

/// Payload bytes that must leave inside one window.
///
/// Ten mebibytes. Large enough that ordinary browsing, mail and a video call do not reach it
/// in a minute; small enough that a stolen document store is caught on the way out rather than
/// after the fact.
const THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

/// How much larger the upload must be than the download.
///
/// Twenty to one. A legitimate large upload that is acknowledged but not answered — a backup
/// to object storage — still exceeds this, which is why confidence is Medium and the advice is
/// to identify the process rather than to block.
const ASYMMETRY_RATIO: u64 = 20;

/// How many address pairs are tracked before the table is cleared.
const MAX_TRACKED: usize = 4_096;

/// Per-pair volume state.
#[derive(Debug)]
struct VolumeState {
    window_start_us: u64,
    outbound_bytes: u64,
    inbound_bytes: u64,
    reported: bool,
}

/// Detects large one-directional uploads from this network to the internet.
#[derive(Debug, Default)]
pub struct VolumeDetector {
    pairs: HashMap<(IpAddr, IpAddr), VolumeState>,
}

impl VolumeDetector {
    /// Creates an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops all state, for a new capture session.
    pub fn reset(&mut self) {
        self.pairs.clear();
    }

    /// Feeds one packet, returning a finding when an upload crosses the thresholds.
    pub(crate) fn observe(&mut self, packet: &NormalizedPacket) -> Option<Observation> {
        if packet.payload_len == 0 {
            return None;
        }

        let (local, remote, outbound) = match (packet.src_ip(), packet.dst_ip()) {
            (Some(source), Some(destination))
                if is_private_addr(source) && !is_private_addr(destination) =>
            {
                (source, destination, true)
            }
            // The reverse direction is counted too, because it is the *absence* of a reply that
            // makes the upload suspicious. A detector that only counted outbound bytes could
            // not tell a backup from a one-way drop.
            (Some(source), Some(destination))
                if !is_private_addr(source) && is_private_addr(destination) =>
            {
                (destination, source, false)
            }
            _ => return None,
        };

        if !is_unicast_remote(remote) {
            return None;
        }

        let now = packet.timestamp_us;
        if self.pairs.len() >= MAX_TRACKED && !self.pairs.contains_key(&(local, remote)) {
            self.pairs.clear();
        }

        let state = self
            .pairs
            .entry((local, remote))
            .or_insert_with(|| VolumeState {
                window_start_us: now,
                outbound_bytes: 0,
                inbound_bytes: 0,
                reported: false,
            });

        if now.saturating_sub(state.window_start_us) > WINDOW_US {
            state.window_start_us = now;
            state.outbound_bytes = 0;
            state.inbound_bytes = 0;
            state.reported = false;
        }

        let bytes = u64::from(packet.payload_len);
        if outbound {
            state.outbound_bytes = state.outbound_bytes.saturating_add(bytes);
        } else {
            state.inbound_bytes = state.inbound_bytes.saturating_add(bytes);
        }

        if state.reported
            || state.outbound_bytes < THRESHOLD_BYTES
            || state.outbound_bytes <= state.inbound_bytes.saturating_mul(ASYMMETRY_RATIO)
        {
            return None;
        }

        state.reported = true;
        let seconds = now.saturating_sub(state.window_start_us) as f64 / 1_000_000.0;
        Some(observation(
            local,
            remote,
            state.outbound_bytes,
            state.inbound_bytes,
            seconds,
            now,
        ))
    }

    /// Number of address pairs currently tracked, for diagnostics.
    #[must_use]
    pub fn tracked_pairs(&self) -> usize {
        self.pairs.len()
    }
}

/// True for a remote address that names one host.
fn is_unicast_remote(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_multicast() && v4 != std::net::Ipv4Addr::BROADCAST && !v4.is_unspecified()
        }
        IpAddr::V6(v6) => !v6.is_multicast() && !v6.is_unspecified(),
    }
}

fn observation(
    local: IpAddr,
    remote: IpAddr,
    outbound: u64,
    inbound: u64,
    seconds: f64,
    now_us: u64,
) -> Observation {
    let mebibytes = outbound as f64 / (1024.0 * 1024.0);
    let ratio = match outbound.checked_div(inbound) {
        Some(ratio) => format!("{ratio}:1"),
        None => "no reply".to_string(),
    };

    Observation {
        id: format!("largeUpload|{local}|{remote}"),
        kind: FindingKind::LargeOutboundTransfer,
        severity: Severity::High,
        confidence: Confidence::Medium,
        title: format!("Large upload from {local} to {remote}"),
        detail: format!(
            "{local} sent {mebibytes:.1} MiB to {remote} in {seconds:.0} seconds, with {ratio} more data leaving than arriving. A large one-way transfer is how data is removed from a network, and also how a backup or a file sync looks."
        ),
        source: Some(local),
        destination: Some(remote),
        at_us: now_us,
        evidence: vec![
            Evidence::new("Bytes sent", outbound.to_string()),
            Evidence::new("Bytes received", inbound.to_string()),
            Evidence::new("Measured over", format!("{seconds:.0} s")),
            Evidence::new("Destination", remote.to_string()),
        ],
        advice: vec![
            "Identify the process and destination before blocking; a backup can look identical to this.",
            "If the destination is not one the organisation recognises, treat the host as compromised.",
            "Preserve the connection record before cleaning up: it is the evidence.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::udp_packet;

    const LOCAL: &str = "192.168.1.20";
    const REMOTE: &str = "198.51.100.7";

    const MIB: u32 = 1024 * 1024;

    fn upload(detector: &mut VolumeDetector, chunks: u32, payload: u32) -> Option<Observation> {
        let mut last = None;
        for index in 0..chunks {
            last = detector.observe(&udp_packet(
                LOCAL,
                REMOTE,
                51_000,
                443,
                1_000_000 + u64::from(index) * 1_000,
                payload,
            ));
        }
        last
    }

    #[test]
    fn ten_mebibytes_leaving_with_no_reply_is_a_finding() {
        let mut detector = VolumeDetector::new();
        let finding = upload(&mut detector, 10, MIB).expect("upload");
        assert_eq!(finding.kind, FindingKind::LargeOutboundTransfer);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert!(finding.detail.contains("no reply"));
    }

    #[test]
    fn just_under_the_threshold_is_not_reported() {
        let mut detector = VolumeDetector::new();
        assert!(upload(&mut detector, 9, MIB).is_none());
    }

    #[test]
    fn an_upload_with_a_matching_reply_is_not_reported() {
        let mut detector = VolumeDetector::new();
        let mut now = 1_000_000;
        // Ten mebibytes out, five back: a video call or a sync, not a one-way drop.
        for _ in 0..10 {
            now += 1_000;
            detector.observe(&udp_packet(LOCAL, REMOTE, 51_000, 443, now, MIB));
            detector.observe(&udp_packet(REMOTE, LOCAL, 443, 51_000, now + 500, MIB / 2));
        }
        assert!(detector.pairs.values().all(|state| !state.reported));
    }

    #[test]
    fn a_large_download_is_not_an_exfiltration_finding() {
        let mut detector = VolumeDetector::new();
        let mut last = None;
        for index in 0..20u64 {
            last = detector.observe(&udp_packet(
                REMOTE,
                LOCAL,
                443,
                51_000,
                1_000_000 + index * 1_000,
                MIB,
            ));
        }
        assert!(
            last.is_none(),
            "inbound traffic must not be reported as an upload"
        );
    }

    #[test]
    fn traffic_between_two_internal_hosts_is_ignored() {
        let mut detector = VolumeDetector::new();
        assert!(
            detector
                .observe(&udp_packet(
                    "192.168.1.20",
                    "192.168.1.30",
                    51_000,
                    445,
                    1,
                    MIB
                ))
                .is_none()
        );
    }

    #[test]
    fn the_upload_is_reported_once_per_window() {
        let mut detector = VolumeDetector::new();
        upload(&mut detector, 10, MIB).expect("first");
        // More data in the same minute is the same upload.
        assert!(upload(&mut detector, 10, MIB).is_none());
    }

    #[test]
    fn a_new_window_can_report_a_new_upload() {
        let mut detector = VolumeDetector::new();
        upload(&mut detector, 10, MIB).expect("first");
        let later = 1_000_000 + WINDOW_US + 1_000;
        let mut last = None;
        for index in 0..10u64 {
            last = detector.observe(&udp_packet(
                LOCAL,
                REMOTE,
                51_000,
                443,
                later + index * 1_000,
                MIB,
            ));
        }
        assert!(
            last.is_some(),
            "a separate upload later must be reported separately"
        );
    }

    #[test]
    fn a_broadcast_destination_is_never_an_upload_destination() {
        let mut detector = VolumeDetector::new();
        for index in 0..10u64 {
            assert!(
                detector
                    .observe(&udp_packet(
                        LOCAL,
                        "255.255.255.255",
                        51_000,
                        9,
                        1_000_000 + index * 1_000,
                        MIB,
                    ))
                    .is_none()
            );
        }
    }

    #[test]
    fn reset_discards_accumulated_volume() {
        let mut detector = VolumeDetector::new();
        upload(&mut detector, 9, MIB);
        detector.reset();
        assert_eq!(detector.tracked_pairs(), 0);
        assert!(upload(&mut detector, 9, MIB).is_none());
    }
}
