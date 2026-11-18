//! Beaconing detection: regular outbound connections, the shape of command-and-control.
//!
//! # The idea, and its limit
//!
//! Malware that keeps a channel open to its operator usually does so on a timer: check in
//! every sixty seconds, receive instructions, sleep again. The *content* is encrypted, so
//! inspecting it is pointless, but the *timing* is a side channel the attacker cannot easily
//! remove without losing reliable command delivery.
//!
//! This detector measures inter-arrival times for connections to one destination and looks for
//! a low coefficient of variation — that is, a mean interval with very little spread.
//!
//! It is deliberately presented as [`crate::FindingKind::PossibleBeaconing`] and
//! [`crate::Confidence::Medium`]. The pattern is also produced by ordinary software: updaters
//! polling on a schedule, monitoring agents, mail clients checking a server, NTP. Those are why
//! the detector requires *many* connections, a *long* minimum interval and a *tight* spread
//! before it says anything at all. Even then it says "possible", because it cannot see intent.
//!
//! # What it does not detect
//!
//! Jittered beacons with a spread wide enough to look like user traffic, and beacons that use
//! fresh connections to a rotating set of addresses. Those need reputation data, which Sentinel
//! does not carry offline. Pretending otherwise would be worse than saying so.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use sentinel_common::net::is_private_addr;
use sentinel_common::packet::NormalizedPacket;

use crate::finding::{Confidence, Evidence, FindingKind, Severity};
use crate::observation::Observation;
use crate::traffic::connection_attempt;

/// How many intervals must be observed before timing means anything.
///
/// Eight intervals is nine connections. A smaller sample lets two coincidentally-equal gaps
/// look like a pattern, which is how a detector earns a reputation for crying wolf.
const MIN_INTERVALS: usize = 8;

/// How many recent intervals are kept per destination.
///
/// Bounded so the estimate can follow a change in cadence instead of averaging in a pattern
/// that stopped an hour ago.
const MAX_INTERVALS: usize = 12;

/// Shortest mean interval considered, in microseconds.
///
/// Five seconds. Anything faster is a request loop or a busy client, not a check-in.
const MIN_MEAN_US: f64 = 5_000_000.0;

/// Longest mean interval considered, in microseconds.
///
/// One hour. Beyond that a "beacon" is a background task, and the operator learns nothing.
const MAX_MEAN_US: f64 = 3_600_000_000.0;

/// Largest coefficient of variation (standard deviation ÷ mean) still considered regular.
///
/// Fifteen percent. A human browsing, a retry with exponential backoff, or a page that polls at
/// a variable rate all exceed this comfortably.
const MAX_JITTER: f64 = 0.15;

/// How many destinations are tracked before the table is pruned.
const MAX_TRACKED: usize = 2_048;

/// How long a destination may go unobserved before it is forgotten.
const IDLE_US: u64 = 2 * 3_600_000_000;

/// Per-destination timing state.
#[derive(Debug)]
struct BeaconState {
    last_us: u64,
    intervals: VecDeque<f64>,
    connections: u64,
    reported: bool,
}

/// Detects connections to one destination at a near-constant interval.
#[derive(Debug, Default)]
pub struct BeaconDetector {
    destinations: HashMap<(IpAddr, IpAddr, u16), BeaconState>,
    observations: u64,
}

impl BeaconDetector {
    /// Creates an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops all state, for a new capture session.
    pub fn reset(&mut self) {
        self.destinations.clear();
        self.observations = 0;
    }

    /// Feeds one packet, returning a finding when regularity is first established.
    pub(crate) fn observe(&mut self, packet: &NormalizedPacket) -> Option<Observation> {
        let (source, destination, port) = connection_attempt(packet)?;
        if source.is_loopback() {
            return None;
        }

        let now = packet.timestamp_us;
        self.observations = self.observations.saturating_add(1);
        if self.observations.is_multiple_of(1_024) {
            self.prune(now);
        }

        let key = (source, destination, port);
        if self.destinations.len() >= MAX_TRACKED && !self.destinations.contains_key(&key) {
            self.prune(now);
            if self.destinations.len() >= MAX_TRACKED {
                self.destinations.clear();
            }
        }

        let state = self.destinations.entry(key).or_insert_with(|| BeaconState {
            last_us: now,
            intervals: VecDeque::with_capacity(MAX_INTERVALS),
            connections: 0,
            reported: false,
        });

        // Only the gap between successive connections is measured. A capture that starts in
        // the middle of a session therefore contributes its first interval one connection in,
        // which is the earliest honest estimate available.
        let gap = now.saturating_sub(state.last_us);
        state.last_us = now;
        state.connections = state.connections.saturating_add(1);

        if gap > 0 {
            if state.intervals.len() == MAX_INTERVALS {
                state.intervals.pop_front();
            }
            state.intervals.push_back(gap as f64);
        }

        if state.reported || state.intervals.len() < MIN_INTERVALS {
            return None;
        }

        let (mean, jitter) = timing(&state.intervals)?;
        if !(MIN_MEAN_US..=MAX_MEAN_US).contains(&mean) || jitter > MAX_JITTER {
            return None;
        }

        // Reported once per destination. Marking before returning means a beacon cannot be
        // reported again by the next packet while the caller is still handling this one.
        state.reported = true;

        Some(observation(
            source,
            destination,
            port,
            mean,
            jitter,
            state.connections,
            now,
        ))
    }

    /// Number of destinations currently tracked, for diagnostics.
    #[must_use]
    pub fn tracked_destinations(&self) -> usize {
        self.destinations.len()
    }

    /// Forgets destinations that have gone quiet.
    fn prune(&mut self, now_us: u64) {
        self.destinations
            .retain(|_, state| now_us.saturating_sub(state.last_us) <= IDLE_US);
    }
}

/// Mean interval and coefficient of variation for a set of gaps.
///
/// Returns `None` when a mean cannot be computed. The caller cannot reach that case with
/// [`MIN_INTERVALS`] gaps, but a helper that returns `NaN` instead of `None` is how a comparison
/// silently becomes false and a real detection disappears.
fn timing(intervals: &VecDeque<f64>) -> Option<(f64, f64)> {
    if intervals.is_empty() {
        return None;
    }
    let count = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / count;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals
        .iter()
        .map(|interval| (interval - mean).powi(2))
        .sum::<f64>()
        / count;
    Some((mean, variance.sqrt() / mean))
}

fn observation(
    source: IpAddr,
    destination: IpAddr,
    port: u16,
    mean_us: f64,
    jitter: f64,
    connections: u64,
    now_us: u64,
) -> Observation {
    let mean_seconds = mean_us / 1_000_000.0;
    let severity = if is_private_addr(destination) {
        // Regular traffic to another host on this network is often a monitoring agent.
        Severity::Medium
    } else {
        Severity::High
    };

    Observation {
        id: format!("beacon|{source}|{destination}|{port}"),
        kind: FindingKind::PossibleBeaconing,
        severity,
        confidence: Confidence::Medium,
        title: format!("Possible beaconing from {source} to {destination}:{port}"),
        detail: format!(
            "{source} contacted {destination}:{port} {connections} times at a near-constant interval of {mean_seconds:.1} seconds (jitter {:.0}%). Regular timing is how malware keeps a command channel open, and it is also how some legitimate software polls a server.",
            jitter * 100.0
        ),
        source: Some(source),
        destination: Some(destination),
        at_us: now_us,
        evidence: vec![
            Evidence::new("Connections observed", connections.to_string()),
            Evidence::new("Mean interval", format!("{mean_seconds:.1} s")),
            Evidence::new("Jitter", format!("{:.0}%", jitter * 100.0)),
            Evidence::new("Destination port", port.to_string()),
        ],
        advice: vec![
            "Identify the process that owns this connection before acting; a health check can look identical to a beacon.",
            "Check whether this destination is one the organisation expects to be contacted.",
            "If the process and destination are both unexplained, treat the host as compromised and investigate its other connections.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{syn, syn_ack, tcp_packet};

    const SRC: &str = "10.0.0.5";
    const DST: &str = "203.0.113.9";

    fn feed_gaps_from(
        detector: &mut BeaconDetector,
        mut now: u64,
        gaps_us: &[u64],
    ) -> Option<Observation> {
        // The first connection establishes a timestamp; every following connection adds one
        // interval, so `n` gaps describe `n + 1` connections.
        let mut last = detector.observe(&tcp_packet(SRC, DST, 51_000, 443, syn(), now));
        for gap in gaps_us {
            now += *gap;
            last = detector.observe(&tcp_packet(SRC, DST, 51_000, 443, syn(), now));
        }
        last
    }

    fn feed_gaps(detector: &mut BeaconDetector, gaps_us: &[u64]) -> Option<Observation> {
        feed_gaps_from(detector, 1_000_000, gaps_us)
    }

    fn feed_even(
        detector: &mut BeaconDetector,
        connections: usize,
        gap_us: u64,
    ) -> Option<Observation> {
        let gaps = vec![gap_us; connections.saturating_sub(1)];
        feed_gaps(detector, &gaps)
    }

    #[test]
    fn eight_connections_are_not_enough() {
        // Seven intervals from eight connections: the detector refuses to call a pattern on a
        // sample this small.
        let mut detector = BeaconDetector::new();
        assert!(feed_even(&mut detector, MIN_INTERVALS, 60_000_000).is_none());
    }

    #[test]
    fn the_ninth_connection_establishes_the_pattern() {
        let mut detector = BeaconDetector::new();
        assert!(feed_even(&mut detector, MIN_INTERVALS + 1, 60_000_000).is_some());
    }

    #[test]
    fn a_steady_sixty_second_check_in_is_reported() {
        let mut detector = BeaconDetector::new();
        let finding = feed_even(&mut detector, MIN_INTERVALS + 1, 60_000_000).expect("beacon");
        assert_eq!(finding.kind, FindingKind::PossibleBeaconing);
        assert_eq!(finding.severity, Severity::High, "external destination");
        assert_eq!(finding.confidence, Confidence::Medium);
        assert!(finding.detail.contains("60.0 seconds"));
        assert!(finding.evidence.iter().any(|e| e.label == "Jitter"));
    }

    #[test]
    fn small_real_world_jitter_is_still_regular() {
        let mut detector = BeaconDetector::new();
        let gaps = [
            61_000_000, 59_500_000, 60_500_000, 60_200_000, 59_800_000, 60_100_000, 60_300_000,
            60_000_000,
        ];
        assert!(feed_gaps(&mut detector, &gaps).is_some());
    }

    #[test]
    fn human_traffic_is_not_regular() {
        let mut detector = BeaconDetector::new();
        let gaps = [
            2_000_000,
            180_000_000,
            5_000_000,
            900_000_000,
            30_000_000,
            400_000_000,
            7_000_000,
            120_000_000,
        ];
        assert!(
            feed_gaps(&mut detector, &gaps).is_none(),
            "wide and irregular gaps must not be reported as a beacon"
        );
    }

    #[test]
    fn a_fast_request_loop_is_below_the_floor() {
        let mut detector = BeaconDetector::new();
        assert!(feed_even(&mut detector, MIN_INTERVALS + 1, 1_000_000).is_none());
    }

    #[test]
    fn a_connection_every_few_hours_is_above_the_ceiling() {
        let mut detector = BeaconDetector::new();
        let gaps = [5 * 3_600_000_000u64; MIN_INTERVALS];
        assert!(feed_gaps(&mut detector, &gaps).is_none());
    }

    #[test]
    fn a_beacon_is_reported_only_once() {
        let mut detector = BeaconDetector::new();
        feed_gaps(&mut detector, &[60_000_000; MIN_INTERVALS]).expect("first report");
        // More check-ins are the same beacon, not a new one.
        let after = 1_000_000 + (MIN_INTERVALS as u64 + 1) * 60_000_000;
        assert!(feed_gaps_from(&mut detector, after, &[60_000_000; MIN_INTERVALS]).is_none());
    }

    #[test]
    fn server_responses_are_not_beaconing() {
        let mut detector = BeaconDetector::new();
        let mut last = None;
        let mut now = 1_000_000;
        for _ in 0..=MIN_INTERVALS {
            now += 60_000_000;
            last = detector.observe(&tcp_packet(DST, SRC, 443, 51_000, syn_ack(), now));
        }
        assert!(last.is_none());
    }

    #[test]
    fn internal_regular_traffic_is_medium_severity() {
        let mut detector = BeaconDetector::new();
        let mut now = 1_000_000;
        let mut last = None;
        for _ in 0..=MIN_INTERVALS {
            now += 60_000_000;
            last = detector.observe(&tcp_packet(SRC, "10.0.0.20", 51_000, 8080, syn(), now));
        }
        assert_eq!(last.expect("beacon").severity, Severity::Medium);
    }

    #[test]
    fn different_destinations_are_tracked_separately() {
        let mut detector = BeaconDetector::new();
        for port in [443, 8443] {
            let mut now = 1_000_000;
            for _ in 0..=MIN_INTERVALS {
                now += 60_000_000;
                detector.observe(&tcp_packet(SRC, DST, 51_000, port, syn(), now));
            }
        }
        assert_eq!(detector.tracked_destinations(), 2);
    }

    #[test]
    fn reset_clears_the_cadence() {
        let mut detector = BeaconDetector::new();
        feed_gaps(&mut detector, &[60_000_000; MIN_INTERVALS]);
        detector.reset();
        assert_eq!(detector.tracked_destinations(), 0);
    }
}
