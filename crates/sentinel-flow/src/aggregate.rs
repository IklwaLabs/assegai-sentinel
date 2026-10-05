//! Traffic aggregation for charts and the overview.
//!
//! Aggregation is deliberately coarse: one bucket per second, holding totals rather than
//! per-packet detail. That is what keeps the UI cheap and the engine's memory flat while
//! still answering "how much traffic, in which direction, over what protocol".

use std::collections::VecDeque;

use sentinel_common::packet::TransportProtocol;
use serde::{Deserialize, Serialize};

/// One second of aggregated traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSample {
    /// Bucket start in microseconds since the Unix epoch.
    pub bucket_start_us: u64,
    /// Bytes uploaded (local to remote).
    pub upload_bytes: u64,
    /// Bytes downloaded (remote to local).
    pub download_bytes: u64,
    /// Packets in the bucket.
    pub packets: u64,
}

impl TrafficSample {
    /// Total bytes in the bucket.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.upload_bytes + self.download_bytes
    }

    /// Bits per second implied by this bucket.
    #[must_use]
    pub fn bits_per_second(&self) -> f64 {
        f64::from(self.total_bytes() as u32) * 8.0
    }
}

/// Per-protocol byte and packet totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolTotals {
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Bytes in both directions.
    pub bytes: u64,
    /// Packets in both directions.
    pub packets: u64,
    /// Distinct flows observed.
    pub flows: u64,
}

/// Totals across the whole session.
///
/// Not `Copy`: it owns a protocol breakdown, and callers get a clone from
/// [`TrafficAggregator::summary`] rather than a cheap copy of shared state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSummary {
    /// Total bytes uploaded.
    pub upload_bytes: u64,
    /// Total bytes downloaded.
    pub download_bytes: u64,
    /// Total packets.
    pub packets: u64,
    /// Session start in microseconds since the Unix epoch.
    pub started_us: u64,
    /// Most recent packet timestamp.
    pub last_packet_us: u64,
    /// Per-protocol breakdown.
    pub protocols: Vec<ProtocolTotals>,
}

impl TrafficSummary {
    /// Total bytes in both directions.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.upload_bytes + self.download_bytes
    }

    /// Session duration in microseconds.
    #[must_use]
    pub const fn duration_us(&self) -> u64 {
        self.last_packet_us.saturating_sub(self.started_us)
    }

    /// Average upload rate in bits per second.
    #[must_use]
    pub fn average_upload_bps(&self) -> f64 {
        self.rate_bps(self.upload_bytes)
    }

    /// Average download rate in bits per second.
    #[must_use]
    pub fn average_download_bps(&self) -> f64 {
        self.rate_bps(self.download_bytes)
    }

    /// Converts a byte count to bits per second over the session.
    ///
    /// A session shorter than one second uses one second as the denominator, so a burst
    /// does not report an absurd instantaneous rate.
    fn rate_bps(&self, bytes: u64) -> f64 {
        let seconds = f64::from(self.duration_us().max(1_000_000) as u32) / 1_000_000.0;
        f64::from(bytes as u32) * 8.0 / seconds
    }

    /// Totals for one protocol, if any packets were seen.
    #[must_use]
    pub fn protocol(&self, protocol: TransportProtocol) -> Option<ProtocolTotals> {
        self.protocols
            .iter()
            .copied()
            .find(|totals| totals.protocol == protocol)
    }
}

/// Rolling window of one-second traffic samples.
///
/// The window is a fixed-size ring: once it is full, the oldest bucket is replaced. Memory is
/// therefore bounded regardless of session length.
pub struct TrafficAggregator {
    buckets: VecDeque<TrafficSample>,
    bucket_count: usize,
    bucket_us: u64,
    summary: TrafficSummary,
    current_bucket_start_us: Option<u64>,
}

impl TrafficAggregator {
    /// Creates an aggregator holding `bucket_count` buckets of `bucket_us` microseconds.
    #[must_use]
    pub fn new(bucket_count: usize, bucket_us: u64) -> Self {
        Self {
            buckets: VecDeque::with_capacity(bucket_count.clamp(1, 3_600)),
            bucket_count: bucket_count.clamp(1, 3_600),
            bucket_us: bucket_us.max(1),
            summary: TrafficSummary::default(),
            current_bucket_start_us: None,
        }
    }

    /// Records one packet.
    ///
    /// `upload` is true when the packet left this machine. Buckets are assigned by
    /// timestamp, so out-of-order packets land in the correct second rather than the
    /// current one.
    pub fn record(&mut self, timestamp_us: u64, bytes: u64, upload: bool) {
        let bucket_start = timestamp_us / self.bucket_us * self.bucket_us;

        if self.summary.started_us == 0 || timestamp_us < self.summary.started_us {
            self.summary.started_us = timestamp_us;
        }
        self.summary.last_packet_us = self.summary.last_packet_us.max(timestamp_us);
        self.summary.packets = self.summary.packets.saturating_add(1);

        if upload {
            self.summary.upload_bytes = self.summary.upload_bytes.saturating_add(bytes);
        } else {
            self.summary.download_bytes = self.summary.download_bytes.saturating_add(bytes);
        }

        match self.current_bucket_start_us {
            // Same second as the newest bucket: accumulate in place.
            Some(current) if current == bucket_start => {
                if let Some(bucket) = self.buckets.back_mut() {
                    if upload {
                        bucket.upload_bytes = bucket.upload_bytes.saturating_add(bytes);
                    } else {
                        bucket.download_bytes = bucket.download_bytes.saturating_add(bytes);
                    }
                    bucket.packets = bucket.packets.saturating_add(1);
                }
            }
            // A later second: append, filling any silent gap first.
            Some(current) if bucket_start > current => {
                self.fill_gap(Some(current), bucket_start);
                self.push_bucket(bucket_start, bytes, upload);
                self.current_bucket_start_us = Some(bucket_start);
            }
            // An earlier second. Capture timestamps are not strictly monotonic (buffering,
            // multi-queue drivers, offline files), so the bucket is merged into its
            // existing position rather than appended out of order.
            _ => self.merge_into(bucket_start, bytes, upload),
        }
    }

    /// Adds a bucket at the end of the window.
    fn push_bucket(&mut self, bucket_start_us: u64, bytes: u64, upload: bool) {
        self.buckets.push_back(TrafficSample {
            bucket_start_us,
            upload_bytes: if upload { bytes } else { 0 },
            download_bytes: if upload { 0 } else { bytes },
            packets: 1,
        });
        self.trim();
    }

    /// Merges a packet into an existing bucket, or creates one at the correct position when
    /// it falls in a gap inside the retained window.
    fn merge_into(&mut self, bucket_start_us: u64, bytes: u64, upload: bool) {
        match self
            .buckets
            .iter()
            .position(|b| b.bucket_start_us == bucket_start_us)
        {
            Some(index) => {
                let bucket = &mut self.buckets[index];
                if upload {
                    bucket.upload_bytes = bucket.upload_bytes.saturating_add(bytes);
                } else {
                    bucket.download_bytes = bucket.download_bytes.saturating_add(bytes);
                }
                bucket.packets = bucket.packets.saturating_add(1);
            }
            None => {
                // Insert in chronological order, then drop whatever falls out of the window.
                let index = self
                    .buckets
                    .iter()
                    .position(|b| b.bucket_start_us > bucket_start_us)
                    .unwrap_or(self.buckets.len());
                self.buckets.insert(
                    index,
                    TrafficSample {
                        bucket_start_us,
                        upload_bytes: if upload { bytes } else { 0 },
                        download_bytes: if upload { 0 } else { bytes },
                        packets: 1,
                    },
                );
                self.trim();
                // The newest bucket is still the newest bucket; only earlier seconds arrived.
                self.current_bucket_start_us = self.buckets.back().map(|b| b.bucket_start_us);
            }
        }
    }

    /// Inserts empty buckets for the gap between two bucket starts.
    fn fill_gap(&mut self, from: Option<u64>, to: u64) {
        let Some(from) = from else { return };
        if to <= from {
            return;
        }
        let mut cursor = from + self.bucket_us;
        while cursor < to {
            self.buckets.push_back(TrafficSample {
                bucket_start_us: cursor,
                ..TrafficSample::default()
            });
            self.trim();
            cursor += self.bucket_us;
        }
    }

    /// Drops the oldest buckets beyond the configured window.
    fn trim(&mut self) {
        while self.buckets.len() > self.bucket_count {
            self.buckets.pop_front();
        }
    }

    /// Adds bytes and a packet count to a protocol's totals, counting one new flow the first
    /// time that protocol is seen.
    ///
    /// `flows` is intentionally not derivable from packet counts: the caller knows when a
    /// flow is created, which the aggregator cannot infer.
    pub fn record_protocol(&mut self, protocol: TransportProtocol, bytes: u64, packets: u64) {
        match self
            .summary
            .protocols
            .iter_mut()
            .find(|totals| totals.protocol == protocol)
        {
            Some(totals) => {
                totals.bytes = totals.bytes.saturating_add(bytes);
                totals.packets = totals.packets.saturating_add(packets);
            }
            None => {
                self.summary.protocols.push(ProtocolTotals {
                    protocol,
                    bytes,
                    packets,
                    flows: 1,
                });
            }
        }
    }

    /// Increments the distinct-flow count for a protocol.
    pub fn record_flow(&mut self, protocol: TransportProtocol) {
        if let Some(totals) = self
            .summary
            .protocols
            .iter_mut()
            .find(|totals| totals.protocol == protocol)
        {
            totals.flows = totals.flows.saturating_add(1);
        }
    }

    /// Number of buckets currently held.
    #[must_use]
    pub fn bucket_len(&self) -> usize {
        self.buckets.len()
    }

    /// Samples in chronological order.
    #[must_use]
    pub fn samples(&self) -> Vec<TrafficSample> {
        self.buckets.iter().copied().collect()
    }

    /// The most recent sample, for a "current rate" reading.
    #[must_use]
    pub fn latest(&self) -> Option<TrafficSample> {
        self.buckets.back().copied()
    }

    /// Session totals, cloned out of the aggregator.
    #[must_use]
    pub fn summary(&self) -> TrafficSummary {
        self.summary.clone()
    }

    /// Resets all state, keeping the configured window size.
    pub fn reset(&mut self) {
        self.buckets.clear();
        self.summary = TrafficSummary::default();
        self.current_bucket_start_us = None;
    }
}

impl Default for TrafficAggregator {
    fn default() -> Self {
        // 120 one-second buckets: two minutes of history, which is what the live chart shows.
        Self::new(120, 1_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregator() -> TrafficAggregator {
        TrafficAggregator::new(4, 1_000_000)
    }

    #[test]
    fn packets_in_the_same_second_share_a_bucket() {
        let mut agg = aggregator();
        agg.record(1_000_000, 100, true);
        agg.record(1_500_000, 200, false);
        agg.record(1_999_999, 300, true);

        assert_eq!(agg.bucket_len(), 1);
        let sample = agg.latest().expect("sample present");
        assert_eq!(sample.bucket_start_us, 1_000_000);
        assert_eq!(sample.upload_bytes, 400);
        assert_eq!(sample.download_bytes, 200);
        assert_eq!(sample.packets, 3);
        assert_eq!(sample.total_bytes(), 600);
        assert_eq!(sample.bits_per_second(), 4800.0);
    }

    #[test]
    fn direction_is_tracked_separately() {
        let mut agg = aggregator();
        agg.record(0, 1_000, true);
        agg.record(1_000_000, 2_000_000, false);

        let summary = agg.summary();
        assert_eq!(summary.upload_bytes, 1_000);
        assert_eq!(summary.download_bytes, 2_000_000);
        assert_eq!(summary.total_bytes(), 2_001_000);
        assert_eq!(summary.packets, 2);
    }

    #[test]
    fn silent_seconds_are_filled_so_charts_keep_their_axis() {
        let mut agg = aggregator();
        agg.record(0, 100, true);
        // Three seconds later: buckets for seconds 1 and 2 must exist and be empty.
        agg.record(3_000_000, 100, true);

        let samples = agg.samples();
        assert_eq!(samples.len(), 4);
        assert_eq!(samples[0].bucket_start_us, 0);
        assert_eq!(samples[1].total_bytes(), 0);
        assert_eq!(samples[2].total_bytes(), 0);
        assert_eq!(samples[3].bucket_start_us, 3_000_000);
    }

    #[test]
    fn the_window_is_bounded() {
        let mut agg = aggregator();
        for second in 0..10 {
            agg.record(second * 1_000_000, 1_000, true);
        }
        assert_eq!(
            agg.bucket_len(),
            4,
            "only the most recent four buckets are kept"
        );

        let samples = agg.samples();
        assert_eq!(samples[0].bucket_start_us, 6_000_000);
        assert_eq!(samples[3].bucket_start_us, 9_000_000);
    }

    #[test]
    fn out_of_order_packets_land_in_the_right_bucket() {
        let mut agg = TrafficAggregator::new(10, 1_000_000);
        agg.record(2_000_000, 500, true);
        agg.record(1_000_000, 300, false);
        agg.record(3_000_000, 100, true);

        let samples = agg.samples();
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[0].total_bytes(), 300);
        assert_eq!(samples[1].total_bytes(), 500);
        assert_eq!(samples[2].total_bytes(), 100);
    }

    #[test]
    fn summary_tracks_the_session_span() {
        let mut agg = TrafficAggregator::new(120, 1_000_000);
        agg.record(10_000_000, 1_000_000, true);
        agg.record(20_000_000, 1_000_000, false);

        let summary = agg.summary();
        assert_eq!(summary.started_us, 10_000_000);
        assert_eq!(summary.last_packet_us, 20_000_000);
        assert_eq!(summary.duration_us(), 10_000_000);
        assert_eq!(summary.average_upload_bps(), 800_000.0);
        assert_eq!(summary.average_download_bps(), 800_000.0);
    }

    #[test]
    fn rates_use_a_one_second_floor_for_very_short_sessions() {
        let mut agg = TrafficAggregator::new(120, 1_000_000);
        agg.record(1_000_000, 1_000_000, true);

        let summary = agg.summary();
        assert_eq!(
            summary.duration_us(),
            0,
            "a single packet has no measurable duration"
        );
        assert_eq!(
            summary.average_upload_bps(),
            8_000_000.0,
            "1 MB in under a second reports as 8 Mbps"
        );
    }

    #[test]
    fn protocol_totals_accumulate_and_are_queryable() {
        let mut agg = aggregator();
        agg.record_protocol(TransportProtocol::Tcp, 5_000, 10);
        agg.record_protocol(TransportProtocol::Tcp, 1_000, 5);
        agg.record_protocol(TransportProtocol::Udp, 200, 1);
        agg.record_flow(TransportProtocol::Tcp);
        agg.record_flow(TransportProtocol::Tcp);

        let summary = agg.summary();
        assert_eq!(summary.protocols.len(), 2);

        let tcp = summary
            .protocol(TransportProtocol::Tcp)
            .expect("tcp totals present");
        assert_eq!(tcp.bytes, 6_000);
        assert_eq!(tcp.packets, 15);
        assert_eq!(
            tcp.flows, 3,
            "first sighting plus two explicit flow creations"
        );

        let udp = summary
            .protocol(TransportProtocol::Udp)
            .expect("udp totals present");
        assert_eq!(udp.flows, 1);
        assert_eq!(udp.packets, 1);

        assert_eq!(summary.protocol(TransportProtocol::Icmp), None);
    }

    #[test]
    fn reset_clears_samples_and_totals() {
        let mut agg = aggregator();
        agg.record(0, 1_000, true);
        agg.record_protocol(TransportProtocol::Tcp, 1_000, 1);
        agg.reset();

        assert_eq!(agg.bucket_len(), 0);
        assert_eq!(agg.summary(), TrafficSummary::default());
        assert_eq!(agg.latest(), None);
    }

    #[test]
    fn the_default_window_is_two_minutes() {
        let mut agg = TrafficAggregator::default();
        for second in 0u64..130 {
            agg.record(second * 1_000_000, 1_000, true);
        }
        assert_eq!(agg.bucket_len(), 120, "two minutes of one-second buckets");
        assert_eq!(
            agg.samples()
                .last()
                .expect("sample present")
                .bucket_start_us,
            129_000_000
        );
    }
}
