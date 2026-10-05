//! The normalized packet pipeline.
//!
//! ```text
//! RawPacket -> validate -> decode -> flow key -> flow update -> aggregate
//! ```
//!
//! Every stage is a plain function of its input. The pipeline holds no state beyond the tables
//! it is given, which is what allows the same code to serve live capture and offline PCAP
//! analysis.
//!
//! # Two hard rules
//!
//! 1. **Decode failures are counted, never fatal.** A malformed frame on a busy network is
//!    normal. The pipeline records it and moves on, because dropping the whole session over one
//!    bad frame would make the tool useless exactly when it is needed.
//! 2. **Payload bytes are not retained.** Only lengths and metadata survive a packet's
//!    lifetime, which is what keeps memory flat under load and honours the privacy defaults.

use std::net::IpAddr;
use std::sync::Arc;

use sentinel_capture::RawPacket;
use sentinel_common::metrics::EngineMetrics;
use sentinel_common::packet::NormalizedPacket;
use sentinel_flow::aggregate::TrafficAggregator;
use sentinel_flow::flow::{Flow, FlowState, FlowUpdate};
use sentinel_flow::key::{FlowKey, FlowSide};
use sentinel_flow::table::{FlowTable, FlowTableConfig};
use sentinel_parser::PacketDecoder;
use serde::{Deserialize, Serialize};

/// Pipeline tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Flow table limits.
    pub flow_table: FlowTableConfig,
    /// Traffic sample bucket width in microseconds.
    pub bucket_us: u64,
    /// Number of traffic sample buckets retained for charts.
    pub bucket_count: usize,
    /// Packets between flow table sweeps.
    pub sweep_interval_packets: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            flow_table: FlowTableConfig::default(),
            bucket_us: 1_000_000,
            bucket_count: 120,
            sweep_interval_packets: 2_000,
        }
    }
}

impl PipelineConfig {
    /// Builds a pipeline configuration from the application's capture settings.
    #[must_use]
    pub fn from_capture_config(capture: &sentinel_common::config::CaptureConfig) -> Self {
        Self {
            flow_table: FlowTableConfig {
                idle_timeout_us: capture.flow_idle_timeout_secs.saturating_mul(1_000_000),
                max_flows: capture.max_tracked_flows,
                sweep_interval_packets: sweep_packets_for(capture.queue_capacity),
            },
            ..Self::default()
        }
    }
}

/// Chooses a sweep cadence proportional to queue capacity, so a fast network sweeps more often
/// without the caller having to know the relationship.
fn sweep_packets_for(queue_capacity: usize) -> u64 {
    (queue_capacity as u64 / 16).clamp(500, 8_192)
}

/// Counters describing what the pipeline has done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineCounters {
    /// Frames offered to the pipeline.
    pub packets_seen: u64,
    /// Frames that decoded successfully.
    pub packets_decoded: u64,
    /// Frames that failed to decode.
    pub decode_errors: u64,
    /// Frames with no flow identity, such as ARP and non-initial fragments.
    pub packets_without_flow: u64,
    /// Snaplen-truncated frames observed.
    pub truncated_packets: u64,
    /// Flows created.
    pub flows_created: u64,
    /// Flow table sweeps performed.
    pub sweeps: u64,
}

/// What the pipeline produced for one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineOutcome {
    /// The decoded packet, present only when decoding succeeded.
    pub packet: Option<NormalizedPacket>,
    /// The flow this frame belonged to.
    pub flow_key: Option<FlowKey>,
    /// Whether the flow was newly created.
    pub flow_created: bool,
}

impl PipelineOutcome {
    /// True when the frame was decoded into a packet.
    #[must_use]
    pub const fn decoded(&self) -> bool {
        self.packet.is_some()
    }
}

/// The decoding and flow-tracking stages.
pub struct Pipeline {
    decoder: PacketDecoder,
    flows: FlowTable,
    aggregator: TrafficAggregator,
    counters: PipelineCounters,
    config: PipelineConfig,
}

impl Pipeline {
    /// Creates a pipeline with the given configuration.
    #[must_use]
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            decoder: PacketDecoder::new(),
            flows: FlowTable::new(config.flow_table),
            aggregator: TrafficAggregator::new(config.bucket_count, config.bucket_us),
            counters: PipelineCounters::default(),
            config,
        }
    }

    /// Declares this machine's addresses so flows can be oriented.
    pub fn set_local_addresses(&mut self, addresses: Vec<IpAddr>) {
        self.flows.set_local_addresses(addresses);
    }

    /// Processes one raw frame.
    ///
    /// `metrics` is passed through to the flow table so its counters stay authoritative for the
    /// whole session.
    pub fn process(&mut self, raw: &RawPacket, metrics: Option<&EngineMetrics>) -> PipelineOutcome {
        self.counters.packets_seen += 1;
        if raw.is_truncated() {
            self.counters.truncated_packets += 1;
        }

        // Stage 1: frame validation and decoding. A failure is counted and reported, never
        // propagated: one bad frame must not end a capture session.
        let packet = match self.decoder.decode(
            raw.data.as_ref(),
            raw.timestamp_us,
            raw.captured_len,
            raw.original_len,
        ) {
            Ok(packet) => {
                self.counters.packets_decoded += 1;
                packet
            }
            Err(err) => {
                self.counters.decode_errors += 1;
                // Debug, not warn: on a busy link this is a normal, high-frequency event and a
                // warning per packet would drown the log.
                tracing::debug!(error = %err, "frame could not be decoded");
                if let Some(metrics) = metrics {
                    metrics.record_decode_error();
                }
                return PipelineOutcome {
                    packet: None,
                    flow_key: None,
                    flow_created: false,
                };
            }
        };

        if let Some(metrics) = metrics {
            metrics.record_decoded();
        }

        // A non-initial IPv4 fragment has an IP header but no transport header, so its ports
        // are unknown. Keying it would create a second, portless flow for a connection that
        // already has one, and the real connection's byte counts would be split in half.
        // Fragments are therefore counted and excluded from flow accounting.
        if packet.is_fragment {
            self.counters.packets_without_flow += 1;
            return PipelineOutcome {
                packet: Some(packet),
                flow_key: None,
                flow_created: false,
            };
        }

        // Stage 2: flow lookup and update. ARP and other non-IP frames have no flow identity.
        let (key, update) = self.flows.apply(&packet, metrics);
        if update == FlowUpdate::Ignored {
            self.counters.packets_without_flow += 1;
            return PipelineOutcome {
                packet: Some(packet),
                flow_key: None,
                flow_created: false,
            };
        }

        if update.is_created() {
            self.counters.flows_created += 1;
            self.aggregator.record_flow(packet.transport_protocol());
        }

        // Stage 3: aggregation. Direction is decided against the initiator, so upload and
        // download totals match what the user sees in the interface's own statistics.
        let upload = self
            .flows
            .get(&key)
            .and_then(|flow| flow.initiator)
            .map(|initiator| packet.src_ip().and_then(|src| key.side_of(src)) == Some(initiator))
            .unwrap_or(true);

        self.aggregator
            .record(packet.timestamp_us, packet.wire_len(), upload);
        self.aggregator
            .record_protocol(packet.transport_protocol(), packet.wire_len(), 1);

        // Stage 4: periodic maintenance. Sweeping here rather than on a timer keeps the whole
        // pipeline in one place and guarantees it happens at a predictable traffic volume.
        if self.flows.should_sweep() {
            let result = self.flows.sweep(packet.timestamp_us, metrics);
            self.counters.sweeps += 1;
            if result.expired > 0 || result.evicted > 0 {
                tracing::debug!(
                    expired = result.expired,
                    evicted = result.evicted,
                    "flow table swept"
                );
            }
        }

        PipelineOutcome {
            packet: Some(packet),
            flow_key: Some(key),
            flow_created: update.is_created(),
        }
    }

    /// Runs a flow table sweep at an explicit time, for callers that want deterministic
    /// maintenance rather than a traffic-proportional cadence.
    pub fn sweep(
        &mut self,
        now_us: u64,
        metrics: Option<&EngineMetrics>,
    ) -> sentinel_flow::table::SweepResult {
        self.counters.sweeps += 1;
        self.flows.sweep(now_us, metrics)
    }

    /// Looks up a flow.
    #[must_use]
    pub fn flow(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    /// Tracked flows, most recently active first.
    #[must_use]
    pub fn flows_by_recent(&self, limit: usize) -> Vec<Flow> {
        self.flows
            .flows_by_recent(limit)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Tracked flows, busiest first.
    #[must_use]
    pub fn flows_by_volume(&self, limit: usize) -> Vec<Flow> {
        self.flows
            .flows_by_volume(limit)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Traffic samples for charting.
    #[must_use]
    pub fn traffic_samples(&self) -> Vec<sentinel_flow::aggregate::TrafficSample> {
        self.aggregator.samples()
    }

    /// Session traffic totals.
    #[must_use]
    pub fn traffic_summary(&self) -> sentinel_flow::aggregate::TrafficSummary {
        self.aggregator.summary()
    }

    /// Current rate, from the newest traffic bucket.
    #[must_use]
    pub fn current_rate_bps(&self) -> (f64, f64) {
        self.aggregator
            .latest()
            .map(|sample| {
                (
                    f64::from(sample.upload_bytes as u32) * 8.0,
                    f64::from(sample.download_bytes as u32) * 8.0,
                )
            })
            .unwrap_or((0.0, 0.0))
    }

    /// Hands every tracked flow to the caller and empties the table.
    pub fn drain_flows(&mut self) -> Vec<Flow> {
        self.flows.drain()
    }

    /// Applies enrichment to a flow.
    pub fn enrich(
        &mut self,
        key: &FlowKey,
        domain: Option<&str>,
        process: Option<sentinel_flow::flow::ProcessRef>,
    ) -> bool {
        self.flows.enrich(key, domain, process)
    }

    /// Applies a risk score to a flow.
    pub fn set_risk(&mut self, key: &FlowKey, score: u8) -> bool {
        self.flows.set_risk(key, score)
    }

    /// Resets all pipeline state, keeping the configuration.
    pub fn reset(&mut self) {
        self.flows = FlowTable::new(self.config.flow_table);
        self.aggregator.reset();
        self.counters = PipelineCounters::default();
    }

    /// Counters for the diagnostics panel.
    #[must_use]
    pub const fn counters(&self) -> PipelineCounters {
        self.counters
    }
}

/// A summary of pipeline health, combining pipeline counters with engine metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineStats {
    /// Pipeline stage counters.
    pub counters: PipelineCounters,
    /// Flows currently tracked.
    pub flows_active: u64,
    /// Ingress queue accounting.
    pub queue: QueueAccounting,
}

/// Ingress accounting, mirrored from the capture queue for display.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueAccounting {
    /// Packets accepted into the queue.
    pub accepted: u64,
    /// Packets dropped because the queue was full.
    pub dropped: u64,
    /// Highest queue depth observed.
    pub high_watermark: u64,
}

impl QueueAccounting {
    /// Builds accounting from a capture queue snapshot.
    #[must_use]
    pub fn from_queue_stats(stats: sentinel_capture::QueueStats) -> Self {
        Self {
            accepted: stats.accepted,
            dropped: stats.dropped,
            high_watermark: stats.high_watermark,
        }
    }

    /// True when the pipeline lost frames to backpressure.
    #[must_use]
    pub const fn has_loss(&self) -> bool {
        self.dropped > 0
    }
}

/// Snapshot helper for callers that need flow state in one call.
pub type FlowSnapshot = Arc<[Flow]>;

/// True when a flow looks finished, used when deciding what to persist.
///
/// A closed flow is one that saw a FIN or RST. Persisting only finished flows would lose
/// long-lived connections, so callers persist on a time cadence too; this helper exists for the
/// flush-on-stop path.
#[must_use]
pub const fn is_finished(flow: &Flow) -> bool {
    matches!(flow.state, FlowState::Closed)
}

/// Convenience: the flow's remote endpoint, when one side is a local address.
#[must_use]
pub fn remote_endpoint(flow: &Flow, local: IpAddr) -> Option<sentinel_flow::key::Endpoint> {
    flow.remote_from(local)
}

/// Convenience: the flow's initiator side, for orientation in the UI.
#[must_use]
pub const fn initiator_side(flow: &Flow) -> Option<FlowSide> {
    flow.initiator
}
