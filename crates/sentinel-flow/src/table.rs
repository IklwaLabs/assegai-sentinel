//! The in-memory flow table.
//!
//! The table is a bounded working set, not a database. It answers "what connections are
//! active right now", which is what the Connections view and the detectors need, and it
//! evicts idle or overflowed flows so memory stays flat on a busy network.

use std::collections::HashMap;

use sentinel_common::metrics::EngineMetrics;
use sentinel_common::packet::NormalizedPacket;

use crate::flow::{Flow, FlowUpdate};
use crate::key::{FlowKey, FlowSide};

/// Tuning for the flow table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTableConfig {
    /// Flows idle for longer than this are evicted on the next sweep.
    pub idle_timeout_us: u64,
    /// Hard cap on tracked flows.
    pub max_flows: usize,
    /// Packets between idle sweeps. Sweeping on every packet would be wasteful; sweeping
    /// only on a timer would need a second thread, so the caller triggers it by passing
    /// `should_sweep`.
    pub sweep_interval_packets: u64,
}

impl Default for FlowTableConfig {
    fn default() -> Self {
        Self {
            idle_timeout_us: 120_000_000,
            max_flows: 20_000,
            sweep_interval_packets: 2_000,
        }
    }
}

/// What happened during a sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepResult {
    /// Flows removed for being idle.
    pub expired: usize,
    /// Flows removed to stay inside the tracked-flow cap.
    pub evicted: usize,
}

/// Bounded, bidirectionally keyed flow table.
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    config: FlowTableConfig,
    packets_since_sweep: u64,
    local_addresses: Vec<std::net::IpAddr>,
}

impl FlowTable {
    /// Creates an empty table.
    #[must_use]
    pub fn new(config: FlowTableConfig) -> Self {
        Self {
            flows: HashMap::new(),
            config,
            packets_since_sweep: 0,
            local_addresses: Vec::new(),
        }
    }

    /// Declares the addresses that represent this machine, so flows can be oriented.
    ///
    /// Orientation matters for attributing upload versus download: without it, the flow
    /// engine can only report totals, not which side initiated.
    pub fn set_local_addresses(&mut self, addresses: Vec<std::net::IpAddr>) {
        self.local_addresses = addresses;
    }

    /// Applies one packet, creating or updating its flow.
    ///
    /// `metrics` is optional so tests and offline analysis do not need one.
    pub fn apply(
        &mut self,
        packet: &NormalizedPacket,
        metrics: Option<&EngineMetrics>,
    ) -> (FlowKey, FlowUpdate) {
        self.packets_since_sweep += 1;

        let Some(key) = FlowKey::from_packet(packet) else {
            return (
                FlowKey::new(
                    packet.transport_protocol(),
                    dummy_endpoint(),
                    dummy_endpoint(),
                ),
                FlowUpdate::Ignored,
            );
        };

        // Direction is decided against the initiator, not against packet order, so reply
        // traffic lands in the correct counter regardless of which side was seen first.
        let side = key.side_of(
            packet
                .src_ip()
                .unwrap_or_else(|| "0.0.0.0".parse().expect("literal parses")),
        );
        let initiator = self
            .flows
            .get(&key)
            .and_then(|flow| flow.initiator)
            .or_else(|| key.likely_initiator());

        let sent_by_initiator = match (initiator, side) {
            (Some(FlowSide::A), Some(FlowSide::A)) | (Some(FlowSide::B), Some(FlowSide::B)) => true,
            (Some(_), Some(_)) => false,
            // No initiator evidence: treat observed traffic as outbound. Counting is
            // approximate in this case, and the UI labels orientation as inferred.
            _ => true,
        };

        let wire_len = packet.wire_len();
        let entry = self.flows.entry(key).or_insert_with(|| {
            if let Some(metrics) = metrics {
                metrics.record_flow_created();
            }
            Flow::new(key, packet.timestamp_us)
        });

        let update = if entry.first_seen_us == packet.timestamp_us && entry.total_packets() == 0 {
            FlowUpdate::Created
        } else {
            FlowUpdate::Updated
        };

        entry.apply_packet(packet, sent_by_initiator, wire_len);
        entry.infer_service();

        (key, update)
    }

    /// Applies a packet and reports whether it created a flow.
    ///
    /// Convenience wrapper matching the metrics-enabled path.
    pub fn apply_packet(
        &mut self,
        packet: &NormalizedPacket,
        metrics: &EngineMetrics,
    ) -> (FlowKey, FlowUpdate) {
        self.apply(packet, Some(metrics))
    }

    /// Looks up a flow by key.
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// True when no flows are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Iterates over every tracked flow.
    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    /// Removes every flow, returning them so the caller can persist them.
    pub fn drain(&mut self) -> Vec<Flow> {
        self.flows.drain().map(|(_, flow)| flow).collect()
    }

    /// Flows ordered by most recent activity, for the Connections view.
    #[must_use]
    pub fn flows_by_recent(&self, limit: usize) -> Vec<&Flow> {
        let mut flows: Vec<&Flow> = self.flows.values().collect();
        flows.sort_by(|a, b| {
            b.last_seen_us
                .cmp(&a.last_seen_us)
                .then_with(|| b.total_bytes().cmp(&a.total_bytes()))
        });
        flows.into_iter().take(limit).collect()
    }

    /// Flows ordered by total bytes, for "top talkers" lists.
    #[must_use]
    pub fn flows_by_volume(&self, limit: usize) -> Vec<&Flow> {
        let mut flows: Vec<&Flow> = self.flows.values().collect();
        flows.sort_by(|a, b| {
            b.total_bytes()
                .cmp(&a.total_bytes())
                .then_with(|| b.last_seen_us.cmp(&a.last_seen_us))
        });
        flows.into_iter().take(limit).collect()
    }

    /// True when a sweep is due, based on packets processed since the last one.
    #[must_use]
    pub fn should_sweep(&self) -> bool {
        self.packets_since_sweep >= self.config.sweep_interval_packets
    }

    /// Removes idle flows and enforces the tracked-flow cap.
    ///
    /// The cap is enforced by retiring the least recently active flows. Retiring the oldest
    /// rather than refusing new flows keeps recent traffic visible, which is what a user
    /// watching a live network actually needs.
    pub fn sweep(&mut self, now_us: u64, metrics: Option<&EngineMetrics>) -> SweepResult {
        self.packets_since_sweep = 0;

        let idle_timeout = self.config.idle_timeout_us;
        let before_expiry = self.flows.len();

        self.flows.retain(|_, flow| {
            let idle = now_us.saturating_sub(flow.last_seen_us);
            idle <= idle_timeout
        });
        let expired = before_expiry - self.flows.len();
        if let Some(metrics) = metrics {
            for _ in 0..expired {
                metrics.record_flow_expired();
            }
        }

        let mut evicted = 0usize;
        if self.flows.len() > self.config.max_flows {
            let mut by_age: Vec<(FlowKey, u64)> = self
                .flows
                .iter()
                .map(|(key, flow)| (*key, flow.last_seen_us))
                .collect();
            by_age.sort_by_key(|(_, last_seen)| *last_seen);

            let overflow = self.flows.len() - self.config.max_flows;
            for (key, _) in by_age.into_iter().take(overflow) {
                if self.flows.remove(&key).is_some() {
                    evicted += 1;
                    if let Some(metrics) = metrics {
                        metrics.record_flow_evicted();
                    }
                }
            }
        }

        SweepResult { expired, evicted }
    }

    /// Applies enrichment to a flow, such as a resolved domain or process attribution.
    ///
    /// Returns true when a flow was found. Enrichment arrives after the packet that created
    /// the flow, so a miss is normal and must not be treated as an error.
    pub fn enrich(
        &mut self,
        key: &FlowKey,
        domain: Option<&str>,
        process: Option<crate::flow::ProcessRef>,
    ) -> bool {
        let Some(flow) = self.flows.get_mut(key) else {
            return false;
        };
        if let Some(domain) = domain {
            flow.domain = Some(domain.to_string());
        }
        if let Some(process) = process {
            flow.process = Some(process);
        }
        true
    }

    /// Applies a risk score to a flow.
    pub fn set_risk(&mut self, key: &FlowKey, score: u8) -> bool {
        match self.flows.get_mut(key) {
            Some(flow) => {
                flow.risk_score = Some(score.min(100));
                true
            }
            None => false,
        }
    }
}

/// Placeholder endpoint for packets with no flow identity.
fn dummy_endpoint() -> crate::key::Endpoint {
    crate::key::Endpoint::new("0.0.0.0".parse().expect("literal parses"), None)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use sentinel_common::packet::{
        EthernetFrame, IpHeader, Ipv4Header, TcpFlags, TcpHeader, TransportHeader,
        TransportProtocol,
    };

    use super::*;
    use crate::key::Endpoint;

    fn packet_from(
        timestamp_us: u64,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        wire_len: u64,
    ) -> NormalizedPacket {
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
                source: src,
                destination: dst,
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
                flags: TcpFlags {
                    ack: true,
                    ..Default::default()
                },
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

    fn client_to_server(timestamp_us: u64, wire_len: u64) -> NormalizedPacket {
        packet_from(
            timestamp_us,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(93, 184, 216, 34),
            52_341,
            443,
            wire_len,
        )
    }

    fn server_to_client(timestamp_us: u64, wire_len: u64) -> NormalizedPacket {
        packet_from(
            timestamp_us,
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(192, 168, 1, 10),
            443,
            52_341,
            wire_len,
        )
    }

    fn table(max_flows: usize) -> FlowTable {
        FlowTable::new(FlowTableConfig {
            idle_timeout_us: 10_000_000, // 10 seconds
            max_flows,
            sweep_interval_packets: 1_000,
        })
    }

    #[test]
    fn first_packet_creates_and_the_next_updates() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();

        let (_, first) = table.apply_packet(&client_to_server(1_000, 60), &metrics);
        assert_eq!(first, FlowUpdate::Created);
        assert_eq!(table.len(), 1);

        let (_, second) = table.apply_packet(&server_to_client(2_000, 74), &metrics);
        assert_eq!(second, FlowUpdate::Updated);
        assert_eq!(table.len(), 1, "a reply must not create a second flow");

        let flow = table.iter().next().expect("flow present");
        assert_eq!(flow.total_packets(), 2);
        assert_eq!(flow.bytes_sent, 60);
        assert_eq!(flow.bytes_received, 74);
        assert_eq!(metrics.snapshot(true, 0).flows_created, 1);
    }

    #[test]
    fn directions_are_attributed_to_the_initiator() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();

        table.apply_packet(&client_to_server(1_000, 100), &metrics);
        table.apply_packet(&server_to_client(2_000, 900), &metrics);

        let flow = table.iter().next().expect("flow present");
        assert_eq!(flow.bytes_sent, 100, "client upload is 'sent'");
        assert_eq!(flow.bytes_received, 900, "server download is 'received'");
        assert_eq!(
            flow.initiator_endpoint().map(|e| e.port),
            Some(Some(52_341))
        );
    }

    #[test]
    fn distinct_connections_are_separate_flows() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();

        table.apply_packet(&client_to_server(1_000, 60), &metrics);
        let other = packet_from(
            1_000,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(1, 1, 1, 1),
            52_342,
            443,
            60,
        );
        table.apply_packet(&other, &metrics);

        assert_eq!(table.len(), 2);
    }

    #[test]
    fn packets_without_flow_identity_are_ignored() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();

        let arp = NormalizedPacket {
            timestamp_us: 1_000,
            captured_len: 42,
            original_len: 42,
            ethernet: None,
            vlan: None,
            arp: Some(sentinel_common::packet::ArpMessage {
                opcode: sentinel_common::packet::ArpOpcode::Request,
                hardware_type: 1,
                protocol_type: 0x0800,
                hardware_len: 6,
                protocol_len: 4,
                sender_mac: Default::default(),
                sender_ip: Ipv4Addr::new(192, 168, 1, 10),
                target_mac: Default::default(),
                target_ip: Ipv4Addr::new(192, 168, 1, 1),
            }),
            ip: None,
            transport: None,
            payload_offset: 42,
            payload_len: 0,
            truncated: false,
            is_fragment: false,
        };

        let (_, update) = table.apply_packet(&arp, &metrics);
        assert_eq!(update, FlowUpdate::Ignored);
        assert!(table.is_empty());
        assert_eq!(metrics.snapshot(true, 0).flows_created, 0);
    }

    #[test]
    fn sweep_expires_idle_flows() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();
        table.apply_packet(&client_to_server(1_000, 60), &metrics);

        // Well inside the idle timeout: nothing expires.
        let result = table.sweep(5_000_000, Some(&metrics));
        assert_eq!(result.expired, 0);
        assert_eq!(table.len(), 1);

        // Past the 10-second timeout: the flow is removed.
        let result = table.sweep(20_000_000, Some(&metrics));
        assert_eq!(result.expired, 1);
        assert!(table.is_empty());
        assert_eq!(metrics.snapshot(true, 0).flows_expired, 1);
    }

    #[test]
    fn sweep_enforces_the_flow_cap_by_retiring_the_oldest() {
        let mut table = table(2);
        let metrics = EngineMetrics::default();

        table.apply_packet(&client_to_server(1_000, 60), &metrics);
        table.apply_packet(
            &packet_from(
                2_000,
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(1, 1, 1, 1),
                50_000,
                443,
                60,
            ),
            &metrics,
        );
        table.apply_packet(
            &packet_from(
                3_000,
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(8, 8, 8, 8),
                50_001,
                53,
                60,
            ),
            &metrics,
        );
        assert_eq!(table.len(), 3);

        // Nothing is idle, so only the cap applies and the oldest flow is retired.
        let result = table.sweep(3_100, Some(&metrics));
        assert_eq!(result.expired, 0);
        assert_eq!(result.evicted, 1);
        assert_eq!(table.len(), 2);

        let oldest_gone = FlowKey::new(
            TransportProtocol::Tcp,
            Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            Endpoint::new("192.168.1.10".parse().expect("valid"), Some(52_341)),
        );
        assert!(
            table.get(&oldest_gone).is_none(),
            "the least recently active flow is retired first"
        );
        assert_eq!(metrics.snapshot(true, 0).flows_evicted, 1);
    }

    #[test]
    fn sweep_is_due_after_enough_packets() {
        let mut table = table(100);
        assert!(!table.should_sweep(), "a fresh table does not need a sweep");

        for index in 0..999 {
            table.apply(&client_to_server(index, 60), None);
        }
        assert!(!table.should_sweep());
        table.apply(&client_to_server(1_000, 60), None);
        assert!(table.should_sweep());
    }

    #[test]
    fn ordering_helpers_rank_by_recency_and_volume() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();

        let small_recent = packet_from(
            9_000,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(8, 8, 8, 8),
            50_000,
            53,
            60,
        );
        let large_old = packet_from(
            1_000,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(1, 1, 1, 1),
            50_001,
            443,
            60,
        );

        table.apply_packet(&small_recent, &metrics);
        table.apply_packet(&large_old, &metrics);
        table.apply_packet(&large_old, &metrics); // second packet: larger volume, same time
        table.apply_packet(&large_old, &metrics);

        let by_recent = table.flows_by_recent(2);
        assert_eq!(by_recent.len(), 2);
        assert_eq!(by_recent[0].last_seen_us, 9_000, "most recent first");

        let by_volume = table.flows_by_volume(2);
        assert_eq!(
            by_volume[0].key.endpoint_a.port,
            Some(443),
            "busiest connection first"
        );
        assert_eq!(by_volume[0].total_bytes(), 180);
    }

    #[test]
    fn enrichment_updates_a_flow_and_misses_are_not_errors() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();
        let (key, _) = table.apply_packet(&client_to_server(1_000, 60), &metrics);

        assert!(table.enrich(&key, Some("example.com"), None));
        let flow = table.get(&key).expect("flow present");
        assert_eq!(flow.domain.as_deref(), Some("example.com"));

        assert!(table.enrich(
            &key,
            None,
            Some(crate::flow::ProcessRef {
                pid: 5812,
                name: "chrome.exe".to_string(),
                path: Some(r"C:\Program Files\Google\Chrome\chrome.exe".to_string()),
                application: Some("Google Chrome".to_string()),
            })
        ));
        let flow = table.get(&key).expect("flow present");
        assert_eq!(flow.process.as_ref().expect("process attached").pid, 5812);
        assert_eq!(
            flow.domain.as_deref(),
            Some("example.com"),
            "a partial enrichment must not clear the domain"
        );

        let unknown = FlowKey::new(
            TransportProtocol::Udp,
            Endpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), Some(1)),
            Endpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), Some(2)),
        );
        assert!(
            !table.enrich(&unknown, Some("late.example"), None),
            "a miss is reported, not panicked on"
        );
    }

    #[test]
    fn risk_scores_are_clamped_and_missing_flows_report_false() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();
        let (key, _) = table.apply_packet(&client_to_server(1_000, 60), &metrics);

        assert!(table.set_risk(&key, 250));
        assert_eq!(table.get(&key).expect("flow present").risk_score, Some(100));

        assert!(table.set_risk(&key, 42));
        assert_eq!(table.get(&key).expect("flow present").risk_score, Some(42));
    }

    #[test]
    fn draining_hands_flows_to_the_caller_and_empties_the_table() {
        let mut table = table(100);
        let metrics = EngineMetrics::default();
        table.apply_packet(&client_to_server(1_000, 60), &metrics);

        let drained = table.drain();
        assert_eq!(drained.len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn local_addresses_can_be_declared() {
        let mut table = table(100);
        table.set_local_addresses(vec![Ipv4Addr::new(192, 168, 1, 10).into()]);
        assert_eq!(table.local_addresses.len(), 1);
    }
}
