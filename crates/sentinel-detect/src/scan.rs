//! Port-scan and host-sweep detection.
//!
//! # Why breadth, not port numbers
//!
//! A detector that fires on "connection to a closed port" is useless: every service discovery
//! protocol, every browser trying the other protocol after a redirect, every IPv6 happy-eyeballs
//! attempt does that constantly. What distinguishes a scan is not any single packet but
//! *breadth in a short time*: many ports on one host, or one port across many hosts.
//!
//! So both rules here count distinct destinations, not packets. A retransmitted SYN is one port,
//! not two, and a browser opening forty connections to `example.com:443` is one host and one
//! port, not forty of either.
//!
//! # Why the thresholds are deliberately high
//!
//! Twenty distinct ports in sixty seconds is roughly an `nmap` default scan of the common
//! ports. A legitimate client contacting twenty distinct services on one host in a minute is
//! rare but not impossible — a monitoring agent or an application with many backends. That is
//! why an internal source is reported as [`Severity::Medium`] rather than High: it may be an
//! administrator doing exactly what they are employed to do. A source outside the local network
//! probing an internal host is another matter, and is reported as High.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;

use sentinel_common::net::is_private_addr;
use sentinel_common::packet::NormalizedPacket;

use crate::finding::{Confidence, Evidence, FindingKind, Severity};
use crate::observation::Observation;
use crate::traffic::connection_attempt;

/// How long a burst of attempts is measured over.
///
/// Sixty seconds is long enough that a slow scan cannot step below the threshold by pausing,
/// and short enough that unrelated activity an hour apart is not added together.
const WINDOW_US: u64 = 60_000_000;

/// Distinct ports on one destination that constitute a port scan.
pub(crate) const VERTICAL_PORTS: usize = 20;

/// Distinct hosts on one port that constitute a sweep.
pub(crate) const HORIZONTAL_HOSTS: usize = 20;

/// How many sources are tracked before the table is emptied.
///
/// A cap is necessary because a spoofed source address is free: an attacker can send one SYN
/// from a million addresses and turn the detector itself into a memory exhaustion bug. When the
/// cap is hit the table is cleared rather than evicted selectively, because the alternative is
/// a least-recently-used structure on the packet path for a case that should never occur on a
/// real network.
const MAX_SOURCES: usize = 1_024;

/// How many destinations, or ports, are tracked per source before that source's table is
/// cleared. The same reasoning as [`MAX_SOURCES`], one level down.
const MAX_TRACKED: usize = 128;

/// How many windows may exist across all sources before the whole table is cleared.
///
/// Per-source caps alone do not bound memory: the number of sources is attacker-controlled too,
/// so their product is still large. This is the ceiling that makes the "bounded state" claim
/// true. Crossing it loses in-progress scan state, which is the conservative direction: a real
/// scan can re-earn its threshold, and nothing is falsely reported.
const MAX_WINDOWS: usize = 8_192;

/// How many distinct values one window remembers.
///
/// Three times the highest threshold, so detection is unaffected, while a single destination
/// cannot grow its port set towards all 65 536 values.
const MAX_WINDOW_VALUES: usize = 64;

/// How many example ports or hosts to include as evidence.
const SAMPLE_LIMIT: usize = 8;

/// A set of distinct values observed inside a sliding window.
#[derive(Debug)]
struct Window<T> {
    start_us: u64,
    seen: HashSet<T>,
}

impl<T: Eq + Hash> Window<T> {
    fn new(now_us: u64) -> Self {
        Self {
            start_us: now_us,
            seen: HashSet::new(),
        }
    }

    /// Records a value and returns how many distinct values the window now holds.
    ///
    /// Expiry resets the whole window rather than removing one old value: a true sliding window
    /// would need a timestamp per entry, and the difference only matters for activity that is
    /// exactly on the boundary. Resetting is also the more conservative behaviour — a scan has
    /// to re-earn its threshold after a quiet minute.
    fn touch(&mut self, value: T, now_us: u64) -> usize {
        if now_us.saturating_sub(self.start_us) > WINDOW_US {
            self.start_us = now_us;
            self.seen.clear();
        }
        // Stop growing once the window has all the evidence any rule needs. Without this a
        // single destination could accumulate a set of every port number.
        if self.seen.len() < MAX_WINDOW_VALUES {
            self.seen.insert(value);
        }
        self.seen.len()
    }

    /// Values as a sorted, limited sample, for evidence.
    fn sample(&self) -> Vec<String>
    where
        T: Ord + std::fmt::Display,
    {
        let mut values: Vec<&T> = self.seen.iter().collect();
        values.sort();
        values
            .into_iter()
            .take(SAMPLE_LIMIT)
            .map(ToString::to_string)
            .collect()
    }
}

/// Per-source scan state.
#[derive(Debug, Default)]
struct SourceState {
    /// Distinct ports contacted, per destination address.
    vertical: HashMap<IpAddr, Window<u16>>,
    /// Distinct hosts contacted, per destination port.
    horizontal: HashMap<u16, Window<IpAddr>>,
}

/// Detects port scans and host sweeps from connection attempts.
#[derive(Debug, Default)]
pub struct ScanDetector {
    sources: HashMap<IpAddr, SourceState>,
    /// Total destination/port windows across every source, so the per-source caps cannot
    /// multiply into unbounded memory.
    windows: usize,
}

impl ScanDetector {
    /// Creates an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops all state, for a new capture session.
    pub fn reset(&mut self) {
        self.sources.clear();
        self.windows = 0;
    }

    /// Feeds one packet, returning the findings it completed.
    ///
    /// The array holds at most one port scan and at most one host sweep, because a fast scanner
    /// can cross both thresholds on the same frame and the two describe different behaviour.
    /// Returning only one would hide half of what the device is doing.
    ///
    /// A threshold is reported on the packet that reaches it, not on every packet after it.
    /// Returning it continuously would make one scan look like hundreds of findings, and the
    /// interface would be unusable exactly when it matters.
    pub(crate) fn observe(&mut self, packet: &NormalizedPacket) -> [Option<Observation>; 2] {
        let Some((source, destination, port)) = connection_attempt(packet) else {
            return [None, None];
        };

        // Multicast and broadcast destinations are one sender addressing many listeners, which
        // is the opposite of a sweep.
        if !is_unicast(destination) || source.is_loopback() {
            return [None, None];
        }

        if self.sources.len() >= MAX_SOURCES && !self.sources.contains_key(&source) {
            self.sources.clear();
            self.windows = 0;
        }

        // The per-source caps multiply, and the number of sources is attacker-controlled, so a
        // global ceiling is what actually bounds memory.
        if self.windows >= MAX_WINDOWS {
            self.sources.clear();
            self.windows = 0;
        }

        let now = packet.timestamp_us;
        let state = self.sources.entry(source).or_default();

        if state.vertical.len() >= MAX_TRACKED || state.horizontal.len() >= MAX_TRACKED {
            self.windows = self
                .windows
                .saturating_sub(state.vertical.len() + state.horizontal.len());
            state.vertical.clear();
            state.horizontal.clear();
        }

        let mut observations = [None, None];

        if !state.vertical.contains_key(&destination) {
            self.windows += 1;
        }
        let ports = state
            .vertical
            .entry(destination)
            .or_insert_with(|| Window::new(now))
            .touch(port, now);
        if ports == VERTICAL_PORTS {
            observations[0] = Some(port_scan(
                source,
                destination,
                state.vertical.get(&destination),
                now,
            ));
        }

        // The sweep rule is checked as well as, not instead of, the port rule: a fast scanner
        // doing both at once produces two accurate findings, and suppressing one would hide
        // half of what it is doing.
        if !state.horizontal.contains_key(&port) {
            self.windows += 1;
        }
        let hosts = state
            .horizontal
            .entry(port)
            .or_insert_with(|| Window::new(now))
            .touch(destination, now);
        if hosts == HORIZONTAL_HOSTS {
            observations[1] = Some(host_sweep(source, port, state.horizontal.get(&port), now));
        }

        observations
    }

    /// Number of sources currently tracked, for diagnostics.
    #[must_use]
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }
}

/// True for addresses that name one recipient.
fn is_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_multicast() && v4 != std::net::Ipv4Addr::BROADCAST && !v4.is_unspecified()
        }
        IpAddr::V6(v6) => !v6.is_multicast() && !v6.is_unspecified(),
    }
}

fn port_scan(
    source: IpAddr,
    destination: IpAddr,
    window: Option<&Window<u16>>,
    now_us: u64,
) -> Observation {
    let ports = window.map_or(0, |window| window.seen.len());
    let seconds = now_us.saturating_sub(window.map_or(now_us, |w| w.start_us)) as f64 / 1_000_000.0;
    let severity = if is_private_addr(source) {
        // A device on this network probing another is worth knowing about, and is also what an
        // administrator's own tooling looks like.
        Severity::Medium
    } else {
        Severity::High
    };

    let sample = window.map(|window| window.sample()).unwrap_or_default();

    Observation {
        id: format!("portScan|{source}|{destination}"),
        kind: FindingKind::PortScan,
        severity,
        confidence: Confidence::High,
        title: format!("Port scan from {source}"),
        detail: format!(
            "{source} opened connections to {ports} different ports on {destination} in {seconds:.0} seconds. Ordinary clients contact a handful of services on a host; this breadth is the shape of a port scan."
        ),
        source: Some(source),
        destination: Some(destination),
        at_us: now_us,
        evidence: vec![
            Evidence::new("Distinct ports contacted", ports.to_string()),
            Evidence::new("Destination", destination.to_string()),
            Evidence::new("Measured over", format!("{seconds:.0} s")),
            Evidence::new("Sample ports", sample.join(", ")),
        ],
        advice: vec![
            "Identify the device at this address before acting; a scanner may be an administrator's own tool.",
            "If the scan was not authorised, isolate the device from the network.",
            "Check the destination host for services that should not be reachable.",
        ],
    }
}

fn host_sweep(
    source: IpAddr,
    port: u16,
    window: Option<&Window<IpAddr>>,
    now_us: u64,
) -> Observation {
    let hosts = window.map_or(0, |window| window.seen.len());
    let seconds = now_us.saturating_sub(window.map_or(now_us, |w| w.start_us)) as f64 / 1_000_000.0;
    let sample = window.map(|window| window.sample()).unwrap_or_default();

    Observation {
        id: format!("hostSweep|{source}|{port}"),
        kind: FindingKind::HostSweep,
        severity: Severity::High,
        confidence: Confidence::High,
        title: format!("Host sweep from {source} on port {port}"),
        detail: format!(
            "{source} tried to reach {hosts} different addresses on port {port} in {seconds:.0} seconds. Contacting many hosts on one port is how a worm or a lateral-movement tool looks for its next victim."
        ),
        source: Some(source),
        destination: None,
        at_us: now_us,
        evidence: vec![
            Evidence::new("Distinct hosts contacted", hosts.to_string()),
            Evidence::new("Port", port.to_string()),
            Evidence::new("Measured over", format!("{seconds:.0} s")),
            Evidence::new("Sample hosts", sample.join(", ")),
        ],
        advice: vec![
            "Identify the device at this address; a sweep is rarely accidental.",
            "Check whether the service on this port is exposed where it should not be.",
            "If the device is not recognised, isolate it from the rest of the network.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ack, syn, syn_ack, tcp_packet};

    const SRC: &str = "10.0.0.5";
    const DST: &str = "10.0.0.9";
    const EXTERNAL: &str = "203.0.113.7";

    fn scan_ports(detector: &mut ScanDetector, count: u16) -> Option<Observation> {
        let mut last = None;
        for offset in 0..count {
            if let Some(finding) = first(detector.observe(&tcp_packet(
                SRC,
                DST,
                40_000 + offset,
                1 + offset,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            ))) {
                last = Some(finding);
            }
        }
        last
    }

    /// True when neither scan rule fired for one packet's result.
    fn quiet(result: [Option<Observation>; 2]) -> bool {
        result.iter().all(Option::is_none)
    }

    /// The first observation in one packet's result, if any.
    fn first(result: [Option<Observation>; 2]) -> Option<Observation> {
        result.into_iter().flatten().next()
    }

    #[test]
    fn one_port_short_of_the_threshold_is_not_a_finding() {
        let mut detector = ScanDetector::new();
        // Nineteen is a busy client, not a scan, and the boundary is asserted on purpose:
        // an off-by-one here decides whether ordinary software is reported as an attacker.
        assert!(scan_ports(&mut detector, (VERTICAL_PORTS - 1) as u16).is_none());
    }

    #[test]
    fn the_port_that_crosses_the_threshold_produces_one_finding() {
        let mut detector = ScanDetector::new();
        let finding = scan_ports(&mut detector, VERTICAL_PORTS as u16).expect("scan");
        assert_eq!(finding.kind, FindingKind::PortScan);
        assert_eq!(finding.severity, Severity::Medium, "internal source");
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.source, Some(SRC.parse().expect("valid")));
        assert_eq!(finding.destination, Some(DST.parse().expect("valid")));
        assert!(finding.detail.contains("20 different ports"));
        assert!(
            finding
                .evidence
                .iter()
                .any(|e| e.label == "Distinct ports contacted")
        );
    }

    #[test]
    fn the_finding_is_not_repeated_for_every_port_after_the_threshold() {
        let mut detector = ScanDetector::new();
        scan_ports(&mut detector, VERTICAL_PORTS as u16).expect("first finding");
        // The twenty-first and twenty-second ports are the same scan, not new scans.
        assert!(quiet(detector.observe(&tcp_packet(
            SRC,
            DST,
            41_000,
            90,
            syn(),
            1_100_000
        ))));
        assert!(quiet(detector.observe(&tcp_packet(
            SRC,
            DST,
            41_001,
            91,
            syn(),
            1_101_000
        ))));
    }

    #[test]
    fn retransmissions_of_one_port_do_not_count_as_breadth() {
        let mut detector = ScanDetector::new();
        for n in 0..40u64 {
            // Same destination port, forty times: a single connection retrying.
            assert!(quiet(detector.observe(&tcp_packet(
                SRC,
                DST,
                40_000,
                443,
                syn(),
                1_000_000 + n * 1_000
            ))));
        }
    }

    #[test]
    fn a_server_answering_is_not_counted_as_scanning() {
        let mut detector = ScanDetector::new();
        for offset in 0..VERTICAL_PORTS as u16 {
            assert!(quiet(detector.observe(&tcp_packet(
                DST,
                SRC,
                443,
                40_000 + offset,
                syn_ack(),
                1_000_000 + u64::from(offset) * 1_000,
            ))));
        }
    }

    #[test]
    fn a_burst_of_data_packets_is_not_a_scan() {
        let mut detector = ScanDetector::new();
        for offset in 0..VERTICAL_PORTS as u16 {
            assert!(quiet(detector.observe(&tcp_packet(
                SRC,
                DST,
                443,
                40_000 + offset,
                ack(),
                1_000_000 + u64::from(offset) * 1_000,
            ))));
        }
    }

    #[test]
    fn activity_spread_past_the_window_does_not_accumulate() {
        let mut detector = ScanDetector::new();
        for offset in 0..(VERTICAL_PORTS as u16 - 1) {
            detector.observe(&tcp_packet(
                SRC,
                DST,
                40_000 + offset,
                1 + offset,
                syn(),
                1_000_000,
            ));
        }
        // One port every two minutes is a slow client, and the window must not add two
        // unrelated minutes together into a scan.
        assert!(quiet(detector.observe(&tcp_packet(
            SRC,
            DST,
            40_100,
            1 + VERTICAL_PORTS as u16,
            syn(),
            1_000_000 + WINDOW_US + 1,
        ))));
    }

    #[test]
    fn an_external_source_scanning_an_internal_host_is_high_severity() {
        let mut detector = ScanDetector::new();
        let mut finding = None;
        for offset in 0..VERTICAL_PORTS as u16 {
            finding = first(detector.observe(&tcp_packet(
                EXTERNAL,
                DST,
                40_000 + offset,
                1 + offset,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            )));
        }
        let finding = finding.expect("scan");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn many_hosts_on_one_port_is_a_sweep_not_a_scan() {
        let mut detector = ScanDetector::new();
        let mut finding = None;
        for offset in 0..HORIZONTAL_HOSTS as u16 {
            finding = first(detector.observe(&tcp_packet(
                SRC,
                &format!("10.0.0.{}", 20 + offset),
                40_000,
                445,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            )));
        }
        let finding = finding.expect("sweep");
        assert_eq!(finding.kind, FindingKind::HostSweep);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.detail.contains("445"));
        assert!(finding.id.starts_with("hostSweep|"));
    }

    #[test]
    fn many_hosts_on_many_ports_is_neither_rule() {
        let mut detector = ScanDetector::new();
        for offset in 0..HORIZONTAL_HOSTS as u16 {
            assert!(quiet(detector.observe(&tcp_packet(
                SRC,
                &format!("10.0.0.{}", 20 + offset),
                40_000,
                1 + offset,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            ))));
        }
    }

    #[test]
    fn a_broadcast_destination_is_not_a_sweep() {
        let mut detector = ScanDetector::new();
        for offset in 0..HORIZONTAL_HOSTS as u16 {
            assert!(quiet(detector.observe(&tcp_packet(
                SRC,
                "255.255.255.255",
                40_000,
                137,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            ))));
        }
    }

    #[test]
    fn separate_sources_are_counted_separately() {
        let mut detector = ScanDetector::new();
        for offset in 0..(VERTICAL_PORTS as u16 / 2) {
            detector.observe(&tcp_packet(
                "10.0.0.5",
                DST,
                40_000 + offset,
                1 + offset,
                syn(),
                1_000_000,
            ));
            detector.observe(&tcp_packet(
                "10.0.0.6",
                DST,
                40_000 + offset,
                1 + offset,
                syn(),
                1_000_000,
            ));
        }
        assert_eq!(detector.tracked_sources(), 2);
    }

    #[test]
    fn a_scan_and_a_sweep_crossing_on_one_packet_are_both_reported() {
        // A fast scanner can complete a host sweep and a port scan on the same frame. Both
        // describe different behaviour, so neither may be dropped.
        let mut detector = ScanDetector::new();
        let destination = "10.0.0.9";
        let sweep_port = 445;

        // Nineteen ports on the target, none of them the sweep port.
        for offset in 0..(VERTICAL_PORTS as u16 - 1) {
            detector.observe(&tcp_packet(
                SRC,
                destination,
                40_000 + offset,
                1 + offset,
                syn(),
                1_000_000 + u64::from(offset) * 1_000,
            ));
        }

        // Nineteen other hosts, all probed on the sweep port.
        for offset in 0..(HORIZONTAL_HOSTS as u16 - 1) {
            detector.observe(&tcp_packet(
                SRC,
                &format!("10.0.1.{}", offset + 1),
                40_000 + offset,
                sweep_port,
                syn(),
                1_500_000 + u64::from(offset) * 1_000,
            ));
        }

        // One frame completes the twentieth port on the target and the twentieth host on the
        // sweep port.
        let result = detector.observe(&tcp_packet(
            SRC,
            destination,
            41_000,
            sweep_port,
            syn(),
            1_600_000,
        ));

        let kinds: Vec<FindingKind> = result
            .into_iter()
            .flatten()
            .map(|observation| observation.kind)
            .collect();
        assert!(
            kinds.contains(&FindingKind::PortScan),
            "the port scan must be reported, got {kinds:?}"
        );
        assert!(
            kinds.contains(&FindingKind::HostSweep),
            "the sweep must be reported, got {kinds:?}"
        );
    }

    #[test]
    fn the_window_table_is_globally_bounded() {
        // Per-source caps multiply with the number of sources, which is attacker-controlled.
        let mut detector = ScanDetector::new();
        for source in 0..MAX_SOURCES as u32 {
            let sender = format!("10.{}.{}.1", (source >> 8) & 0xff, source & 0xff);
            for destination in 0..16u32 {
                detector.observe(&tcp_packet(
                    &sender,
                    &format!("192.168.{}.1", destination + 1),
                    40_000,
                    445,
                    syn(),
                    1_000_000 + u64::from(destination),
                ));
            }
        }
        assert!(
            detector.windows <= MAX_WINDOWS,
            "windows must be capped globally, got {}",
            detector.windows
        );
    }

    #[test]
    fn one_window_remembers_a_bounded_number_of_values() {
        let mut detector = ScanDetector::new();
        for port in 0..1_000u16 {
            detector.observe(&tcp_packet(SRC, DST, 40_000, 1 + port, syn(), 1_000_000));
        }
        let source: IpAddr = SRC.parse().expect("valid");
        let destination: IpAddr = DST.parse().expect("valid");
        let window = &detector.sources[&source].vertical[&destination];
        assert_eq!(
            window.seen.len(),
            MAX_WINDOW_VALUES,
            "a single destination must not accumulate every port number"
        );
    }

    #[test]
    fn reset_discards_partial_state() {
        let mut detector = ScanDetector::new();
        scan_ports(&mut detector, (VERTICAL_PORTS - 1) as u16);
        detector.reset();
        assert_eq!(detector.tracked_sources(), 0);
        assert!(quiet(detector.observe(&tcp_packet(
            SRC,
            DST,
            40_000,
            1,
            syn(),
            1_000_000
        ))));
    }

    #[test]
    fn multicast_is_not_treated_as_a_destination_to_sweep() {
        assert!(!is_unicast("224.0.0.251".parse().expect("valid")));
        assert!(!is_unicast("ff02::fb".parse().expect("valid")));
        assert!(is_unicast("10.0.0.1".parse().expect("valid")));
    }
}
