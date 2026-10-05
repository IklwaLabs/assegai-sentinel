//! Ingress queue between the capture thread and the engine.
//!
//! The capture thread must never block because the consumer is slow: a stalled parser would
//! back up into the driver, which would then drop packets. Instead the queue is bounded, the
//! producer uses `try_send`, and every refusal increments a counter the UI displays.
//!
//! Overflow is handled *intentionally*, which is the whole point: an unbounded queue turns a
//! throughput problem into an out-of-memory crash, and a silently lossy queue makes the
//! statistics a lie.
//!
//! # Two halves, because the queue crosses a thread boundary
//!
//! `std::sync::mpsc`'s `Receiver` is `Send` but not `Sync`, so it cannot live behind an `Arc`
//! shared between the capture thread and the engine. The queue is therefore split:
//!
//! - [`PacketIngress`] — the producer half. Holds the sender; `Sync`; shared behind an `Arc`.
//! - [`PacketConsumer`] — the consumer half. Holds the receiver; `Send`; owned by the engine.
//!
//! Both halves read the same counters, which live behind an `Arc<Counters>` so "how much was
//! lost" has exactly one answer regardless of which side is asked. [`channel`] creates both.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};

use crate::provider::RawPacket;

/// What happened when a packet was offered to the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    /// The packet was queued.
    Accepted,
    /// The queue was full, or the consumer was gone, so the packet was dropped and counted.
    Dropped,
}

/// Counters shared by both halves of the queue.
#[derive(Debug, Default)]
struct Counters {
    depth: AtomicUsize,
    accepted: AtomicU64,
    dropped: AtomicU64,
    high_watermark: AtomicU64,
}

impl Counters {
    /// A snapshot of the queue's accounting.
    fn snapshot(&self) -> QueueStats {
        QueueStats {
            depth: self.depth.load(Ordering::Relaxed),
            accepted: self.accepted.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            high_watermark: self.high_watermark.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of ingress accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueStats {
    /// Packets currently waiting.
    pub depth: usize,
    /// Packets accepted since creation.
    pub accepted: u64,
    /// Packets dropped because the queue was full or closed.
    pub dropped: u64,
    /// Highest depth ever observed.
    pub high_watermark: u64,
}

impl QueueStats {
    /// Share of offered packets that were dropped, in `0.0..=1.0`.
    #[must_use]
    pub fn drop_ratio(&self) -> f64 {
        let total = self.accepted + self.dropped;
        if total == 0 {
            return 0.0;
        }
        self.dropped as f64 / total as f64
    }

    /// True when the queue has lost at least one packet.
    #[must_use]
    pub const fn has_loss(&self) -> bool {
        self.dropped > 0
    }
}

/// Producer half of the ingress queue.
///
/// Shared with the capture thread behind an `Arc`. Drops are counted here rather than reported
/// as events, because a per-packet event on overflow would amplify the very overload it is
/// reporting.
pub struct PacketIngress {
    /// `None` once closed, which is how the consumer learns the source has finished.
    sender: Option<SyncSender<RawPacket>>,
    counters: Arc<Counters>,
    capacity: usize,
}

/// Consumer half of the ingress queue.
pub struct PacketConsumer {
    receiver: Receiver<RawPacket>,
    counters: Arc<Counters>,
}

/// Creates a bounded ingress queue and its two halves.
///
/// # Panics
/// Never: a zero capacity is clamped to one, since a zero-capacity channel would block or
/// refuse every send.
#[must_use]
pub fn channel(capacity: usize) -> (PacketIngress, PacketConsumer) {
    let capacity = capacity.max(1);
    let (sender, receiver) = sync_channel(capacity);
    let counters = Arc::new(Counters::default());
    (
        PacketIngress {
            sender: Some(sender),
            counters: Arc::clone(&counters),
            capacity,
        },
        PacketConsumer { receiver, counters },
    )
}

impl PacketIngress {
    /// Offers a packet without blocking.
    pub fn push(&self, packet: RawPacket) -> EnqueueResult {
        let Some(sender) = self.sender.as_ref() else {
            self.record_drop();
            return EnqueueResult::Dropped;
        };

        match sender.try_send(packet) {
            Ok(()) => {
                self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                let depth = self.counters.depth.fetch_add(1, Ordering::Relaxed) + 1;
                self.counters
                    .high_watermark
                    .fetch_max(depth as u64, Ordering::Relaxed);
                EnqueueResult::Accepted
            }
            Err(TrySendError::Full(_)) => {
                self.record_drop();
                EnqueueResult::Dropped
            }
            Err(TrySendError::Disconnected(_)) => {
                // The engine has stopped. Counting the drop keeps the loss visible instead of
                // pretending the packet was delivered.
                self.record_drop();
                EnqueueResult::Dropped
            }
        }
    }

    /// Offers a packet and returns `1` when accepted, `0` when dropped.
    ///
    /// The count form suits bulk loading, where the caller wants a running total rather than a
    /// per-packet decision.
    pub fn push_counted(&self, packet: RawPacket) -> usize {
        usize::from(self.push(packet) == EnqueueResult::Accepted)
    }

    /// Closes the queue so the consumer can observe end-of-stream.
    ///
    /// Already-queued packets remain readable, so a clean shutdown does not discard buffered
    /// frames. Later pushes are refused and counted, which makes a late capture thread harmless.
    pub fn close(&mut self) {
        self.sender = None;
    }

    /// True once the queue has been closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.sender.is_none()
    }

    /// Configured capacity in packets.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current accounting.
    #[must_use]
    pub fn stats(&self) -> QueueStats {
        self.counters.snapshot()
    }

    fn record_drop(&self) {
        self.counters.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

impl PacketConsumer {
    /// Takes the next packet, if any, without blocking.
    #[must_use]
    pub fn try_next(&self) -> Option<RawPacket> {
        match self.receiver.try_recv() {
            Ok(packet) => {
                // Saturating: a spurious underflow would report a huge depth, and the counter
                // must never go negative even if a future refactor double-decrements.
                let _ =
                    self.counters
                        .depth
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                            Some(value.saturating_sub(1))
                        });
                Some(packet)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }

    /// Returns an iterator yielding packets until the queue closes and drains.
    pub fn iter(&self) -> PacketIter<'_> {
        PacketIter { consumer: self }
    }

    /// Blocks until a packet arrives or the queue closes and drains.
    #[must_use]
    pub fn blocking_next(&self) -> Option<RawPacket> {
        self.receiver.recv().ok().inspect(|_| {
            let _ = self
                .counters
                .depth
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                });
        })
    }

    /// Current accounting.
    #[must_use]
    pub fn stats(&self) -> QueueStats {
        self.counters.snapshot()
    }
}

/// Iterator over queued packets.
pub struct PacketIter<'a> {
    consumer: &'a PacketConsumer,
}

impl Iterator for PacketIter<'_> {
    type Item = RawPacket;

    fn next(&mut self) -> Option<Self::Item> {
        self.consumer.try_next()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn packet(id: u8) -> RawPacket {
        RawPacket::new(u64::from(id), 60, 60, Bytes::from(vec![id; 4]))
    }

    #[test]
    fn packets_are_delivered_in_order() {
        let (ingress, consumer) = channel(8);
        for id in 0..4 {
            assert_eq!(ingress.push(packet(id)), EnqueueResult::Accepted);
        }
        assert_eq!(consumer.stats().depth, 4);

        for id in 0..4 {
            assert_eq!(consumer.try_next().expect("packet queued").data[0], id);
        }
        assert_eq!(consumer.try_next(), None);
        assert_eq!(
            consumer.stats().depth,
            0,
            "the depth must return to zero as it drains"
        );
    }

    #[test]
    fn overflow_is_counted_rather_than_blocking() {
        let (ingress, _consumer) = channel(2);
        assert_eq!(ingress.push(packet(1)), EnqueueResult::Accepted);
        assert_eq!(ingress.push(packet(2)), EnqueueResult::Accepted);
        assert_eq!(ingress.push(packet(3)), EnqueueResult::Dropped);
        assert_eq!(ingress.push(packet(4)), EnqueueResult::Dropped);

        let stats = ingress.stats();
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.dropped, 2);
        assert!((stats.drop_ratio() - 0.5).abs() < f64::EPSILON);
        assert!(stats.has_loss());
    }

    #[test]
    fn a_full_queue_never_blocks_the_producer() {
        let (ingress, _consumer) = channel(4);
        let total = 10_000u64;
        let started = std::time::Instant::now();
        for id in 0..total {
            // Only the first bytes are distinctive; the counter above is what matters here.
            let _ = ingress.push(packet((id % 251) as u8));
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "pushing {total} packets into a 4-slot queue must not block"
        );
        assert_eq!(ingress.stats().dropped, total - 4);
    }

    #[test]
    fn draining_makes_room_again() {
        let (ingress, consumer) = channel(2);
        ingress.push(packet(1));
        ingress.push(packet(2));
        assert_eq!(ingress.push(packet(3)), EnqueueResult::Dropped);

        consumer.try_next().expect("a packet to drain");
        assert_eq!(
            ingress.push(packet(4)),
            EnqueueResult::Accepted,
            "a freed slot must be reusable"
        );
    }

    #[test]
    fn the_high_watermark_reflects_peak_depth() {
        let (ingress, consumer) = channel(10);
        for id in 0..6 {
            ingress.push(packet(id));
        }
        assert_eq!(ingress.stats().high_watermark, 6);

        for _ in 0..6 {
            consumer.try_next().expect("packet queued");
        }
        assert_eq!(consumer.stats().depth, 0);
        assert_eq!(
            consumer.stats().high_watermark,
            6,
            "the peak is remembered after draining"
        );
    }

    #[test]
    fn both_halves_report_the_same_counters() {
        let (ingress, consumer) = channel(4);
        ingress.push(packet(1));
        ingress.push(packet(2));
        ingress.push(packet(3));

        assert_eq!(
            ingress.stats(),
            consumer.stats(),
            "one source of truth for loss accounting"
        );
    }

    #[test]
    fn an_unread_queue_reports_no_drops() {
        let (ingress, _consumer) = channel(4);
        assert_eq!(ingress.stats().drop_ratio(), 0.0);
        assert!(!ingress.stats().has_loss());
    }

    #[test]
    fn capacity_is_at_least_one() {
        let (ingress, _consumer) = channel(0);
        assert_eq!(ingress.capacity(), 1, "a zero capacity would deadlock");
    }

    #[test]
    fn a_closed_queue_refuses_packets_and_keeps_what_it_had() {
        let (mut ingress, consumer) = channel(4);
        ingress.push(packet(1));
        assert!(!ingress.is_closed());

        ingress.close();
        assert!(ingress.is_closed());

        // Already-queued frames remain readable so a clean shutdown does not lose them.
        assert_eq!(consumer.try_next().map(|p| p.data[0]), Some(1));

        assert_eq!(
            ingress.push(packet(2)),
            EnqueueResult::Dropped,
            "a closed queue accepts nothing"
        );
        assert_eq!(ingress.stats().dropped, 1);
    }

    #[test]
    fn iteration_yields_every_queued_packet() {
        let (ingress, consumer) = channel(16);
        for id in 0..5 {
            ingress.push(packet(id));
        }
        let ids: Vec<u8> = consumer.iter().map(|p| p.data[0]).collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn bulk_counting_matches_per_packet_results() {
        let (ingress, _consumer) = channel(2);
        assert_eq!(ingress.push_counted(packet(1)), 1);
        assert_eq!(ingress.push_counted(packet(2)), 1);
        assert_eq!(
            ingress.push_counted(packet(3)),
            0,
            "the third packet exceeds capacity"
        );
    }
}
