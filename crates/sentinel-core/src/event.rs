//! Engine events.
//!
//! The engine publishes **aggregate** snapshots, not per-packet events. Two reasons:
//!
//! 1. React (or any consumer) must never receive a stream of packet events; the UI coalesces
//!    to a configurable rate and would spend all its time re-rendering.
//! 2. Per-packet events would couple the engine's throughput to the slowest subscriber, which
//!    is the coupling the whole queue design exists to avoid.
//!
//! The event stream is therefore a heartbeat: a periodic `Snapshot` carrying everything a view
//! needs, plus `StateChanged` when the session transitions, so a UI can react to
//! start/stop/failure without polling.

use std::sync::Arc;

use sentinel_common::config::AppConfig;
use sentinel_common::error::UserMessage;
use sentinel_common::metrics::MetricsSnapshot;
use sentinel_common::net::NetworkInterface;
use serde::{Deserialize, Serialize};

use crate::pipeline::{PipelineStats, QueueAccounting};
use crate::session::SessionState;

/// What kind of event this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EventKind {
    /// The session state changed.
    StateChanged,
    /// A periodic aggregate snapshot.
    Snapshot,
    /// Something the user must be told about, already formatted for display.
    Notice,
}

/// One traffic bucket, as the chart consumes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPoint {
    /// Bucket start in microseconds since the Unix epoch.
    pub at_us: u64,
    /// Upload bytes in this bucket.
    pub upload_bytes: u64,
    /// Download bytes in this bucket.
    pub download_bytes: u64,
    /// Packets in this bucket.
    pub packets: u64,
}

impl From<sentinel_flow::aggregate::TrafficSample> for TrafficPoint {
    fn from(sample: sentinel_flow::aggregate::TrafficSample) -> Self {
        Self {
            at_us: sample.bucket_start_us,
            upload_bytes: sample.upload_bytes,
            download_bytes: sample.download_bytes,
            packets: sample.packets,
        }
    }
}

/// One connection row, shaped for the Connections table.
///
/// The engine projects the internal flow into this rather than exposing `Flow` directly, so the
/// API contract is a deliberate surface rather than an accident of internal field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRow {
    /// Stable identifier for the connection, derived from its flow key.
    pub id: String,
    /// The side that opened the connection, as `address:port`.
    ///
    /// Orientation here is by **initiator**, which the flow key cannot know and which is derived
    /// from port roles. That is a different fact from "this machine", so the two are reported
    /// separately: a table can say "Chrome talked to example.com" without claiming the capture
    /// belongs to this host.
    pub source: String,
    /// The side that responded.
    pub destination: String,
    /// True when Sentinel could tell which side opened the connection. False when both ports
    /// are ephemeral or both are service ports, in which case source and destination fall back to
    /// the key's canonical order.
    pub initiator_known: bool,
    /// This machine's endpoint, when one of the two belongs to a monitored interface.
    pub local: Option<String>,
    /// The other end, when this machine's endpoint is known.
    pub remote: Option<String>,
    /// Transport protocol label.
    pub protocol: String,
    /// Resolved domain, when known.
    pub domain: Option<String>,
    /// Inferred service name, when known.
    pub service: Option<String>,
    /// Process name, when resolvable.
    pub process: Option<String>,
    /// Observed connection state label.
    pub state: String,
    /// Upload bytes.
    pub upload_bytes: u64,
    /// Download bytes.
    pub download_bytes: u64,
    /// Total packets.
    pub packets: u64,
    /// First packet timestamp.
    pub first_seen_us: u64,
    /// Most recent packet timestamp.
    pub last_seen_us: u64,
    /// Risk score, absent until the risk engine runs.
    pub risk_score: Option<u8>,
    /// Alerts attributed to this connection.
    pub alert_count: u32,
}

impl ConnectionRow {
    /// Projects a flow into a table row without orientation.
    ///
    /// With no local addresses to compare against, `local` is `endpoint_a` and `orientation_known`
    /// is false. Callers that know this machine's addresses should use
    /// [`ConnectionRow::from_flow_oriented`].
    #[must_use]
    pub fn from_flow(flow: &sentinel_flow::flow::Flow) -> Self {
        Self::from_flow_oriented(flow, &[])
    }

    /// Projects a flow into a table row, oriented against this machine's addresses.
    ///
    /// `local_addresses` comes from the monitored interface. Source and destination are always
    /// oriented by initiator; `local`/`remote` are filled only when one endpoint matches, so a
    /// view never claims a local side it cannot justify.
    #[must_use]
    pub fn from_flow_oriented(
        flow: &sentinel_flow::flow::Flow,
        local_addresses: &[std::net::IpAddr],
    ) -> Self {
        use sentinel_flow::key::FlowSide;
        use sentinel_storage::FlowRecord;

        let record = FlowRecord::new(flow.clone());

        let (source, destination, initiator_known) = match flow.initiator {
            Some(FlowSide::A) => (flow.key.endpoint_a, flow.key.endpoint_b, true),
            Some(FlowSide::B) => (flow.key.endpoint_b, flow.key.endpoint_a, true),
            // No port evidence for a direction: fall back to the canonical order and say so.
            None => (flow.key.endpoint_a, flow.key.endpoint_b, false),
        };

        let (local, remote) = if local_addresses.contains(&flow.key.endpoint_a.addr) {
            (
                Some(flow.key.endpoint_a.display()),
                Some(flow.key.endpoint_b.display()),
            )
        } else if local_addresses.contains(&flow.key.endpoint_b.addr) {
            (
                Some(flow.key.endpoint_b.display()),
                Some(flow.key.endpoint_a.display()),
            )
        } else {
            (None, None)
        };

        Self {
            id: record.id,
            source: source.display(),
            destination: destination.display(),
            initiator_known,
            local,
            remote,
            protocol: flow.key.protocol.label().to_string(),
            domain: flow.domain.clone(),
            service: flow.service.clone(),
            process: flow.process.as_ref().map(|process| {
                process
                    .application
                    .clone()
                    .unwrap_or_else(|| process.name.clone())
            }),
            state: flow.state.label().to_string(),
            upload_bytes: flow.bytes_sent,
            download_bytes: flow.bytes_received,
            packets: flow.total_packets(),
            first_seen_us: flow.first_seen_us,
            last_seen_us: flow.last_seen_us,
            risk_score: flow.risk_score,
            alert_count: flow.alert_count,
        }
    }

    /// Total bytes in both directions.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.upload_bytes + self.download_bytes
    }
}

impl EngineSnapshot {
    /// Observed span in microseconds, or `0` when no frame has been seen.
    #[must_use]
    pub fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }

    /// True when at least one frame has been observed.
    #[must_use]
    pub const fn has_traffic(&self) -> bool {
        self.total_packets > 0
    }
}

/// Everything a view needs in one payload.
///
/// Views read from a snapshot rather than assembling state from several events, which keeps the
/// frontend a renderer instead of a reducer of a Rust-side event stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineSnapshot {
    /// Session state.
    pub state: SessionState,
    /// Interface being monitored, when one is selected.
    pub interface: Option<NetworkInterface>,
    /// Traffic totals for the session.
    pub total_upload_bytes: u64,
    /// Traffic totals for the session.
    pub total_download_bytes: u64,
    /// Total packets observed.
    pub total_packets: u64,
    /// Timestamp of the first frame seen, in microseconds since the Unix epoch.
    ///
    /// Travels with the snapshot so a view can show a capture's true span without inferring it
    /// from bucket boundaries, which are quantised to whole seconds.
    pub first_seen_us: u64,
    /// Timestamp of the most recent frame seen.
    pub last_seen_us: u64,
    /// Upload rate in bits per second, from the newest bucket.
    pub upload_bps: f64,
    /// Download rate in bits per second, from the newest bucket.
    pub download_bps: f64,
    /// Chart series, oldest first.
    pub traffic: Vec<TrafficPoint>,
    /// Most recent connections, newest first.
    pub connections: Vec<ConnectionRow>,
    /// Number of tracked flows.
    pub flows_active: u64,
    /// Pipeline and queue counters.
    pub stats: PipelineStats,
    /// Engine-level counters.
    pub metrics: MetricsSnapshot,
    /// Effective configuration, so the UI can display the real values in force.
    pub config: AppConfig,
}

/// An event published by the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "payload")]
pub enum EngineEvent {
    /// The session state changed.
    StateChanged(SessionState),
    /// A periodic snapshot.
    Snapshot(Arc<EngineSnapshot>),
    /// A message for the user, already phrased for display.
    Notice(UserMessage),
}

impl EngineEvent {
    /// This event's kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        match self {
            EngineEvent::StateChanged(_) => EventKind::StateChanged,
            EngineEvent::Snapshot(_) => EventKind::Snapshot,
            EngineEvent::Notice(_) => EventKind::Notice,
        }
    }

    /// The snapshot, when this is a snapshot event.
    #[must_use]
    pub fn snapshot(&self) -> Option<&Arc<EngineSnapshot>> {
        match self {
            EngineEvent::Snapshot(snapshot) => Some(snapshot),
            _ => None,
        }
    }

    /// True for state transitions, which a UI should react to rather than coalesce.
    #[must_use]
    pub const fn is_state_change(&self) -> bool {
        matches!(self, EngineEvent::StateChanged(_))
    }
}

/// Broadcast helper for engine events.
///
/// Subscribers receive events independently: a slow or absent subscriber never blocks the
/// engine, and a subscriber that cannot keep up misses snapshots rather than packets. The
/// engine's own counters record that the broadcast happened, so the loss remains visible.
#[derive(Clone, Default)]
pub struct EventBroadcaster {
    subscribers:
        std::sync::Arc<std::sync::RwLock<Vec<tokio::sync::mpsc::UnboundedSender<EngineEvent>>>>,
}

impl std::fmt::Debug for EventBroadcaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBroadcaster")
            .field("subscribers", &self.subscriber_count())
            .finish()
    }
}

impl EventBroadcaster {
    /// Creates a broadcaster with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a subscriber and returns its receiving end.
    ///
    /// The queue is unbounded because a snapshot is a complete replacement rather than an
    /// incremental update: a subscriber that falls behind gets the next snapshot and is
    /// correct again, and a bounded queue would drop the *newest* state, which is the one that
    /// matters. Snapshots arrive at a few hertz, so the queue cannot grow without bound in
    /// practice.
    pub fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<EngineEvent> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        if let Ok(mut subscribers) = self.subscribers.write() {
            subscribers.push(sender);
        } else {
            tracing::warn!(
                "event subscriber list is poisoned; this subscriber will receive no events"
            );
        }
        receiver
    }

    /// Publishes an event to every subscriber.
    pub fn publish(&self, event: EngineEvent) {
        let Ok(mut subscribers) = self.subscribers.write() else {
            tracing::warn!("event subscriber list is poisoned; event not published");
            return;
        };
        // A closed receiver means the subscriber went away. Removing it here keeps the list
        // from growing for the life of the process.
        subscribers.retain(|sender| sender.send(event.clone()).is_ok());
    }

    /// Number of live subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().map(|list| list.len()).unwrap_or(0)
    }

    /// Drops subscribers whose receivers have been closed.
    ///
    /// Called opportunistically so an abandoned subscriber does not hold a queue entry until
    /// the next publish. `publish` already prunes, so this is an optimisation, not a
    /// correctness requirement.
    pub fn prune(&self) {
        if let Ok(mut subscribers) = self.subscribers.write() {
            subscribers.retain(|sender| !sender.is_closed());
        }
    }
}

/// Queue accounting helper for snapshot construction.
#[must_use]
pub fn queue_accounting(stats: sentinel_capture::QueueStats) -> QueueAccounting {
    QueueAccounting::from_queue_stats(stats)
}

#[cfg(test)]
mod tests {
    use sentinel_common::packet::TransportProtocol;
    use sentinel_flow::flow::{Flow, FlowState};
    use sentinel_flow::key::{Endpoint, FlowKey};

    use super::*;

    fn sample_flow() -> Flow {
        Flow {
            key: FlowKey::new(
                TransportProtocol::Tcp,
                Endpoint::new("192.168.1.10".parse().expect("valid"), Some(52_341)),
                Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            ),
            state: FlowState::Established,
            first_seen_us: 1_000,
            last_seen_us: 5_000,
            bytes_sent: 100,
            bytes_received: 900,
            packets_sent: 2,
            packets_received: 4,
            service: Some("HTTPS".to_string()),
            domain: Some("example.com".to_string()),
            process: Some(sentinel_flow::flow::ProcessRef {
                pid: 5812,
                name: "chrome.exe".to_string(),
                path: None,
                application: Some("Google Chrome".to_string()),
            }),
            risk_score: Some(35),
            alert_count: 1,
            tags: Default::default(),
            initiator: Some(sentinel_flow::key::FlowSide::B),
        }
    }

    #[test]
    fn connection_rows_project_the_fields_the_table_needs() {
        let row = ConnectionRow::from_flow(&sample_flow());

        assert_eq!(row.protocol, "TCP");
        assert_eq!(row.domain.as_deref(), Some("example.com"));
        assert_eq!(row.service.as_deref(), Some("HTTPS"));
        // The friendly application name is preferred over the raw executable name.
        assert_eq!(row.process.as_deref(), Some("Google Chrome"));
        assert_eq!(row.state, "Active");
        assert_eq!(row.upload_bytes, 100);
        assert_eq!(row.download_bytes, 900);
        assert_eq!(row.packets, 6);
        assert_eq!(row.total_bytes(), 1_000);
        assert_eq!(row.risk_score, Some(35));
        assert!(
            row.id.contains("tcp"),
            "the id should identify the protocol"
        );
    }

    /// The flow key orders endpoints canonically, so a row must say which side opened the
    /// connection rather than implying the canonical order is a direction.
    #[test]
    fn rows_are_oriented_by_initiator() {
        let flow = sample_flow();
        // Canonical ordering puts the server (93.184.216.34:443) in endpoint_a, while the
        // ephemeral client port identifies the client as the initiator.
        assert_eq!(flow.key.endpoint_a.display(), "93.184.216.34:443");

        let row = ConnectionRow::from_flow_oriented(&flow, &[]);
        assert!(row.initiator_known);
        assert_eq!(
            row.source, "192.168.1.10:52341",
            "the client opened the connection"
        );
        assert_eq!(row.destination, "93.184.216.34:443");
    }

    #[test]
    fn rows_report_the_local_side_only_when_it_is_known() {
        let flow = sample_flow();
        let local: std::net::IpAddr = "192.168.1.10".parse().expect("valid");

        let oriented = ConnectionRow::from_flow_oriented(&flow, &[local]);
        assert_eq!(oriented.local.as_deref(), Some("192.168.1.10:52341"));
        assert_eq!(oriented.remote.as_deref(), Some("93.184.216.34:443"));

        // A capture that does not involve this machine must not claim a local side.
        let foreign =
            ConnectionRow::from_flow_oriented(&flow, &["10.9.9.9".parse().expect("valid")]);
        assert_eq!(foreign.local, None);
        assert_eq!(foreign.remote, None);
    }

    #[test]
    fn rows_without_port_evidence_say_the_direction_is_unknown() {
        let mut flow = sample_flow();
        flow.initiator = None;
        let row = ConnectionRow::from_flow_oriented(&flow, &[]);

        assert!(
            !row.initiator_known,
            "symmetric ports give no basis for a direction claim"
        );
        // The canonical order is still a stable, truthful pair, just not a direction.
        assert_eq!(row.source, "93.184.216.34:443");
        assert_eq!(row.destination, "192.168.1.10:52341");
    }

    #[test]
    fn rows_are_stable_regardless_of_orientation() {
        let flow = sample_flow();
        let local: std::net::IpAddr = "192.168.1.10".parse().expect("valid");
        assert_eq!(
            ConnectionRow::from_flow(&flow).id,
            ConnectionRow::from_flow_oriented(&flow, &[local]).id,
            "the identifier must not depend on which side is local"
        );
    }

    #[test]
    fn a_flow_without_a_process_still_projects() {
        let mut flow = sample_flow();
        flow.process = None;
        flow.domain = None;
        let row = ConnectionRow::from_flow(&flow);
        assert_eq!(row.process, None);
        assert_eq!(row.domain, None);
    }

    #[test]
    fn traffic_points_convert_from_aggregator_samples() {
        let point = TrafficPoint::from(sentinel_flow::aggregate::TrafficSample {
            bucket_start_us: 1_000_000,
            upload_bytes: 100,
            download_bytes: 200,
            packets: 3,
        });
        assert_eq!(point.at_us, 1_000_000);
        assert_eq!(point.upload_bytes, 100);
        assert_eq!(point.packets, 3);
    }

    #[test]
    fn events_carry_their_kind() {
        let state_event = EngineEvent::StateChanged(SessionState::Idle);
        assert_eq!(state_event.kind(), EventKind::StateChanged);
        assert!(state_event.is_state_change());
        assert!(state_event.snapshot().is_none());

        let snapshot = EngineEvent::Snapshot(Arc::new(EngineSnapshot {
            state: SessionState::Monitoring {
                interface: "3".to_string(),
                interface_name: "Ethernet".to_string(),
            },
            interface: None,
            total_upload_bytes: 0,
            total_download_bytes: 0,
            total_packets: 0,
            first_seen_us: 0,
            last_seen_us: 0,
            upload_bps: 0.0,
            download_bps: 0.0,
            traffic: Vec::new(),
            connections: Vec::new(),
            flows_active: 0,
            stats: PipelineStats::default(),
            metrics: MetricsSnapshot::default(),
            config: AppConfig::default(),
        }));
        assert_eq!(snapshot.kind(), EventKind::Snapshot);
        assert!(snapshot.snapshot().is_some());
        assert!(!snapshot.is_state_change());
    }

    #[test]
    fn events_serialize_with_a_tagged_shape() {
        let json = serde_json::to_string(&EngineEvent::StateChanged(SessionState::Monitoring {
            interface: "3".to_string(),
            interface_name: "Ethernet".to_string(),
        }))
        .expect("serialize state change");
        assert!(json.contains("\"kind\":\"stateChanged\""), "{json}");
        assert!(json.contains("monitoring"), "{json}");
    }

    #[test]
    fn subscribers_receive_published_events() {
        let broadcaster = EventBroadcaster::new();
        let mut receiver = broadcaster.subscribe();
        assert_eq!(broadcaster.subscriber_count(), 1);

        broadcaster.publish(EngineEvent::StateChanged(SessionState::Monitoring {
            interface: "3".to_string(),
            interface_name: "Ethernet".to_string(),
        }));
        let event = receiver.try_recv().expect("event delivered");
        assert!(event.is_state_change());
    }

    #[test]
    fn a_dropped_subscriber_is_removed_rather_than_leaked() {
        let broadcaster = EventBroadcaster::new();
        let receiver = broadcaster.subscribe();
        assert_eq!(broadcaster.subscriber_count(), 1);

        drop(receiver);
        broadcaster.publish(EngineEvent::StateChanged(SessionState::Idle));
        assert_eq!(
            broadcaster.subscriber_count(),
            0,
            "a closed subscriber must not accumulate"
        );
    }

    #[test]
    fn publishing_without_subscribers_is_harmless() {
        let broadcaster = EventBroadcaster::new();
        broadcaster.publish(EngineEvent::StateChanged(SessionState::Idle));
        assert_eq!(broadcaster.subscriber_count(), 0);
    }

    #[test]
    fn queue_accounting_reflects_capture_loss() {
        let accounting = queue_accounting(sentinel_capture::QueueStats {
            depth: 4,
            accepted: 100,
            dropped: 3,
            high_watermark: 64,
        });
        assert!(accounting.has_loss());
        assert_eq!(accounting.dropped, 3);
        assert_eq!(accounting.high_watermark, 64);
    }
}
