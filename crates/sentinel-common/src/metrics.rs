//! Engine counters.
//!
//! Metrics exist to make the pipeline honest: if packets are dropped, the number must
//! be visible in the UI and the CLI rather than hidden inside the capture thread. All
//! counters are relaxed atomics because they are advisory statistics, not
//! synchronisation.

use std::sync::atomic::{AtomicU64, Ordering};

/// Live counters for one engine session.
#[derive(Debug, Default)]
pub struct EngineMetrics {
    packets_captured: AtomicU64,
    bytes_captured: AtomicU64,
    packets_dropped: AtomicU64,
    packets_decoded: AtomicU64,
    decode_errors: AtomicU64,
    queue_high_watermark: AtomicU64,
    flows_created: AtomicU64,
    flows_evicted: AtomicU64,
    flows_active: AtomicU64,
    flows_expired: AtomicU64,
    packets_written: AtomicU64,
    ui_events_emitted: AtomicU64,
}

/// An immutable view of [`EngineMetrics`], suitable for serialization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSnapshot {
    /// Frames returned by the capture backend.
    pub packets_captured: u64,
    /// Bytes returned by the capture backend.
    pub bytes_captured: u64,
    /// Frames discarded because the ingress queue was full.
    pub packets_dropped: u64,
    /// Frames successfully decoded.
    pub packets_decoded: u64,
    /// Frames that could not be decoded (counted, not fatal).
    pub decode_errors: u64,
    /// Highest observed ingress queue depth.
    pub queue_high_watermark: u64,
    /// Current number of tracked flows.
    pub flows_active: u64,
    /// Flows created since the session started.
    pub flows_created: u64,
    /// Flows evicted to stay inside the tracked-flow cap.
    pub flows_evicted: u64,
    /// Flows removed after exceeding the idle timeout.
    pub flows_expired: u64,
    /// Flow records committed to storage.
    pub packets_written: u64,
    /// Aggregate snapshots broadcast to subscribers.
    pub ui_events_emitted: u64,
    /// Whether the engine is currently capturing.
    pub capturing: bool,
    /// Capture backend reports of its own kernel-side drops, when available.
    pub backend_dropped: u64,
}

impl MetricsSnapshot {
    /// Share of captured packets that were dropped due to backpressure, in `0.0..=1.0`.
    ///
    /// Returns `0.0` before any packet has been seen.
    #[must_use]
    pub fn drop_ratio(&self) -> f64 {
        let total = self.packets_captured + self.packets_dropped;
        if total == 0 {
            return 0.0;
        }
        self.packets_dropped as f64 / total as f64
    }
}

impl EngineMetrics {
    /// Records a frame returned by the capture backend.
    pub fn record_captured(&self, bytes: u64) {
        self.packets_captured.fetch_add(1, Ordering::Relaxed);
        self.bytes_captured.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records frames discarded because the ingress queue was full.
    pub fn record_dropped(&self, count: u64) {
        self.packets_dropped.fetch_add(count, Ordering::Relaxed);
    }

    /// Records a successful decode.
    pub fn record_decoded(&self) {
        self.packets_decoded.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a decode failure.
    pub fn record_decode_error(&self) {
        self.decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a newly created flow.
    pub fn record_flow_created(&self) {
        self.flows_created.fetch_add(1, Ordering::Relaxed);
        self.flows_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a flow removed to respect the tracked-flow cap.
    pub fn record_flow_evicted(&self) {
        self.flows_evicted.fetch_add(1, Ordering::Relaxed);
        decrement(&self.flows_active);
    }

    /// Records a flow removed after the idle timeout.
    pub fn record_flow_expired(&self) {
        self.flows_expired.fetch_add(1, Ordering::Relaxed);
        decrement(&self.flows_active);
    }

    /// Records flow records written to storage.
    pub fn record_written(&self, count: u64) {
        self.packets_written.fetch_add(count, Ordering::Relaxed);
    }

    /// Records an aggregate snapshot broadcast.
    pub fn record_ui_event(&self) {
        self.ui_events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Updates the ingress queue high-water mark.
    pub fn observe_queue_depth(&self, depth: u64) {
        self.queue_high_watermark
            .fetch_max(depth, Ordering::Relaxed);
    }

    /// Returns a consistent-enough snapshot for display.
    #[must_use]
    pub fn snapshot(&self, capturing: bool, backend_dropped: u64) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_captured: self.packets_captured.load(Ordering::Relaxed),
            bytes_captured: self.bytes_captured.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_decoded: self.packets_decoded.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            queue_high_watermark: self.queue_high_watermark.load(Ordering::Relaxed),
            flows_active: self.flows_active.load(Ordering::Relaxed),
            flows_created: self.flows_created.load(Ordering::Relaxed),
            flows_evicted: self.flows_evicted.load(Ordering::Relaxed),
            flows_expired: self.flows_expired.load(Ordering::Relaxed),
            packets_written: self.packets_written.load(Ordering::Relaxed),
            ui_events_emitted: self.ui_events_emitted.load(Ordering::Relaxed),
            capturing,
            backend_dropped,
        }
    }
}

/// Decrements a counter, saturating at zero.
///
/// Removals can be reported by more than one path (idle sweep, capacity eviction, table
/// reset), so an underflow here would display a nonsense active-flow count.
fn decrement(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_snapshot() {
        let metrics = EngineMetrics::default();
        metrics.record_captured(100);
        metrics.record_captured(60);
        metrics.record_decoded();
        metrics.record_decode_error();
        metrics.record_flow_created();
        metrics.record_flow_created();
        metrics.record_flow_expired();
        metrics.record_written(2);
        metrics.record_ui_event();
        metrics.observe_queue_depth(12);
        metrics.observe_queue_depth(5);
        metrics.record_dropped(1);

        let snap = metrics.snapshot(true, 3);
        assert_eq!(snap.packets_captured, 2);
        assert_eq!(snap.bytes_captured, 160);
        assert_eq!(snap.packets_decoded, 1);
        assert_eq!(snap.decode_errors, 1);
        assert_eq!(snap.flows_created, 2);
        assert_eq!(snap.flows_active, 1);
        assert_eq!(snap.flows_expired, 1);
        assert_eq!(snap.queue_high_watermark, 12);
        assert_eq!(snap.packets_written, 2);
        assert_eq!(snap.ui_events_emitted, 1);
        assert_eq!(snap.backend_dropped, 3);
        assert!(snap.capturing);
    }

    #[test]
    fn drop_ratio_reflects_backpressure() {
        let metrics = EngineMetrics::default();
        assert_eq!(metrics.snapshot(false, 0).drop_ratio(), 0.0);
        metrics.record_captured(1);
        metrics.record_captured(1);
        metrics.record_captured(1);
        metrics.record_dropped(1);
        assert!((metrics.snapshot(true, 0).drop_ratio() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn removals_saturate_instead_of_underflowing() {
        let metrics = EngineMetrics::default();
        metrics.record_flow_created();
        metrics.record_flow_evicted();
        metrics.record_flow_expired();
        assert_eq!(metrics.snapshot(false, 0).flows_active, 0);

        // A removal reported without a matching creation must not wrap to u64::MAX.
        metrics.record_flow_expired();
        assert_eq!(metrics.snapshot(false, 0).flows_active, 0);
    }
}
