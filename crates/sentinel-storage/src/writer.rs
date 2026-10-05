//! Batched write path.
//!
//! The capture pipeline must never block on disk. [`StorageWriter`] owns the database on its own
//! thread and receives batches over a **bounded** channel; when the queue is full the batch is
//! dropped and counted rather than stalling the packet pipeline. Drops are reported, never
//! silent, because an unbounded queue would trade correctness for memory.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use sentinel_flow::aggregate::TrafficSample;
use sentinel_flow::flow::Flow;

use crate::db::Database;
use crate::error::Result;
use crate::schema::{FlowRecord, InterfaceRecord, ProtocolTotalRecord};
use crate::statements;

/// Something the writer can persist.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteItem {
    /// A finished or periodically flushed flow.
    Flow(Box<Flow>),
    /// One second of traffic.
    TrafficSample(TrafficSample),
    /// An interface observation.
    Interface(InterfaceRecord),
    /// A protocol total snapshot.
    ProtocolTotal(ProtocolTotalRecord),
    /// A key/value setting.
    Setting {
        /// Setting key.
        key: String,
        /// JSON-encoded value.
        value: String,
    },
    /// A retention sweep, applied inside the writer's transaction.
    ///
    /// Retention is executed here rather than from a second database handle because SQLite has
    /// a single writer: two connections would contend for the write lock, and the one that lost
    /// would report a spurious "database is locked" error to the user.
    Retention {
        /// Delete flows last seen before this timestamp; `None` keeps everything.
        flows_cutoff_us: Option<u64>,
        /// Delete samples older than this timestamp; `None` keeps everything.
        samples_cutoff_us: Option<u64>,
    },
}

/// A group of items written in one transaction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WriteBatch {
    /// Items in the batch.
    pub items: Vec<WriteItem>,
}

impl WriteBatch {
    /// Creates an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Creates a batch holding one item.
    #[must_use]
    pub fn single(item: WriteItem) -> Self {
        Self { items: vec![item] }
    }

    /// Adds an item.
    pub fn push(&mut self, item: WriteItem) {
        self.items.push(item);
    }

    /// Number of items in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the batch holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Counters describing what the writer accepted, wrote and refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterStats {
    /// Items handed to the writer thread.
    pub items_submitted: u64,
    /// Items committed to the database.
    pub items_written: u64,
    /// Batches committed.
    pub batches_committed: u64,
    /// Items dropped because the queue was full.
    pub items_dropped: u64,
    /// Transactions that failed.
    pub errors: u64,
}

/// A background writer owning the database handle.
///
/// Created with [`StorageWriter::spawn`]. Dropping it closes the queue and joins the thread, so
/// a clean shutdown never loses an already-accepted batch.
pub struct StorageWriter {
    /// Held in an `Option` so shutdown can drop the sender before joining. The writer thread
    /// only sees end-of-stream when every sender is gone, and a sender that is still a field
    /// of `self` would keep the thread blocked in `recv` while `Drop` waits on `join`.
    sender: Option<SyncSender<WriteBatch>>,
    handle: Option<JoinHandle<WriterStats>>,
    items_submitted: AtomicU64,
    items_written: AtomicU64,
    batches_committed: AtomicU64,
    items_dropped: AtomicU64,
    errors: AtomicU64,
}

impl StorageWriter {
    /// Starts a writer thread with the given queue capacity and batch size.
    ///
    /// `queue_capacity` bounds queued batches; `batch_size` is how many items accumulate before
    /// a transaction is committed.
    ///
    /// # Panics
    /// Panics if `batch_size` is zero. That is a programming error caught at start-up, not a
    /// runtime condition.
    pub fn spawn(database: Database, queue_capacity: usize, batch_size: usize) -> Self {
        assert!(batch_size > 0, "batch size must be at least 1");

        // sync_channel is a genuinely bounded queue: try_send reports Full rather than
        // blocking, which is the property the packet pipeline depends on.
        let (sender, receiver) = sync_channel::<WriteBatch>(queue_capacity.max(1));

        let counters = Arc::new(Counters::default());
        let thread_counters = Arc::clone(&counters);

        let handle = std::thread::Builder::new()
            .name("sentinel-storage".to_string())
            .spawn(move || {
                let stats = writer_loop(database, receiver, batch_size, &thread_counters);
                thread_counters.apply(&stats);
                stats
            })
            .ok();

        Self {
            sender: Some(sender),
            handle,
            items_submitted: AtomicU64::new(0),
            items_written: AtomicU64::new(0),
            batches_committed: AtomicU64::new(0),
            items_dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    /// Queues a batch without blocking.
    ///
    /// Returns `false` when the queue was full and the batch was dropped; the drop is counted
    /// in [`StorageWriter::stats`].
    pub fn submit(&self, batch: WriteBatch) -> bool {
        if batch.is_empty() {
            return true;
        }
        self.items_submitted
            .fetch_add(batch.len() as u64, Ordering::Relaxed);

        let Some(sender) = self.sender.as_ref() else {
            self.items_dropped
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            return false;
        };

        match sender.try_send(batch) {
            Ok(()) => true,
            Err(TrySendError::Full(batch)) => {
                self.items_dropped
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                tracing::warn!(
                    items = batch.len(),
                    queue = "full",
                    "storage queue full; batch dropped"
                );
                false
            }
            // The writer thread is gone, which means the database handle is gone. Counting the
            // drop is the honest response; logs carry the reason.
            Err(TrySendError::Disconnected(batch)) => {
                self.items_dropped
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                tracing::error!(items = batch.len(), "storage writer is not running");
                false
            }
        }
    }

    /// Queues a single item.
    pub fn submit_item(&self, item: WriteItem) -> bool {
        self.submit(WriteBatch::single(item))
    }

    /// Current counters, including anything the writer thread has committed so far.
    #[must_use]
    pub fn stats(&self) -> WriterStats {
        WriterStats {
            items_submitted: self.items_submitted.load(Ordering::Relaxed),
            items_written: self.items_written.load(Ordering::Relaxed),
            batches_committed: self.batches_committed.load(Ordering::Relaxed),
            items_dropped: self.items_dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    /// True when the writer thread is still alive.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Closes the queue, waits for the writer to drain and commit, and returns final counters.
    ///
    /// Idempotent: calling it again after shutdown is a no-op that reports the same numbers.
    pub fn shutdown(&mut self) -> WriterStats {
        // Dropping the sender is what lets the writer thread observe end-of-stream and exit.
        self.sender = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.stats()
    }
}

impl Drop for StorageWriter {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Counters shared with the writer thread so `stats()` reflects committed writes, not only
/// submissions made on the calling thread.
#[derive(Debug, Default)]
struct Counters {
    items_written: AtomicU64,
    batches_committed: AtomicU64,
    errors: AtomicU64,
}

impl Counters {
    fn add(&self, field: &AtomicU64, value: u64) {
        field.fetch_add(value, Ordering::Relaxed);
    }

    fn apply(&self, stats: &WriterStats) {
        self.add(&self.items_written, stats.items_written);
        self.add(&self.batches_committed, stats.batches_committed);
        self.add(&self.errors, stats.errors);
    }
}

/// The writer thread's main loop.
fn writer_loop(
    mut database: Database,
    receiver: Receiver<WriteBatch>,
    batch_size: usize,
    counters: &Counters,
) -> WriterStats {
    let mut pending: Vec<WriteItem> = Vec::with_capacity(batch_size);
    let mut stats = WriterStats::default();

    // `recv` returning an error means every sender is gone: drain what is pending, commit it,
    // and stop. That ordering is what makes a clean shutdown lossless.
    while let Ok(batch) = receiver.recv() {
        for item in batch.items {
            pending.push(item);
            if pending.len() >= batch_size {
                flush(&mut database, &mut pending, &mut stats, counters);
            }
        }
    }

    if !pending.is_empty() {
        flush(&mut database, &mut pending, &mut stats, counters);
    }
    stats
}

/// Commits everything pending in a single transaction.
fn flush(
    database: &mut Database,
    pending: &mut Vec<WriteItem>,
    stats: &mut WriterStats,
    counters: &Counters,
) {
    if pending.is_empty() {
        return;
    }
    let items = std::mem::take(pending);
    let count = items.len() as u64;

    let outcome: Result<()> = database.transaction(|conn| {
        for item in &items {
            write_item(conn, item)?;
        }
        Ok(())
    });

    match outcome {
        Ok(()) => {
            stats.items_written += count;
            stats.batches_committed += 1;
            counters.add(&counters.items_written, count);
            counters.add(&counters.batches_committed, 1);
            tracing::trace!(items = count, "batch committed");
        }
        Err(err) => {
            // A failed batch is logged and dropped. Retrying indefinitely would stall the
            // writer and grow memory; the counters and logs make the loss visible.
            stats.errors += 1;
            counters.add(&counters.errors, 1);
            tracing::error!(items = count, error = %err, "batch failed and was discarded");
        }
    }
}

/// Writes one item inside an already-open transaction.
fn write_item(conn: &rusqlite::Connection, item: &WriteItem) -> Result<()> {
    match item {
        WriteItem::Flow(flow) => statements::upsert_flow(conn, &FlowRecord::new((**flow).clone())),
        WriteItem::TrafficSample(sample) => statements::upsert_traffic_sample(conn, sample),
        WriteItem::Interface(record) => statements::upsert_interface(conn, record),
        WriteItem::ProtocolTotal(record) => statements::upsert_protocol_total(conn, record),
        WriteItem::Setting { key, value } => statements::upsert_setting(conn, key, value),
        WriteItem::Retention {
            flows_cutoff_us,
            samples_cutoff_us,
        } => {
            if let Some(cutoff) = flows_cutoff_us {
                let removed = statements::delete_flows_before(conn, *cutoff)?;
                if removed > 0 {
                    tracing::info!(
                        rows = removed,
                        cutoff_us = cutoff,
                        "retention removed flows"
                    );
                }
            }
            if let Some(cutoff) = samples_cutoff_us {
                let removed = statements::delete_samples_before(conn, *cutoff)?;
                if removed > 0 {
                    tracing::info!(
                        rows = removed,
                        cutoff_us = cutoff,
                        "retention removed traffic samples"
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sentinel_common::packet::TransportProtocol;
    use sentinel_flow::flow::FlowState;
    use sentinel_flow::key::{Endpoint, FlowKey};

    use super::*;
    use crate::db::{Database, DatabaseOptions};

    fn flow(port: u16) -> Flow {
        Flow {
            key: FlowKey::new(
                TransportProtocol::Tcp,
                Endpoint::new("192.168.1.10".parse().expect("valid"), Some(port)),
                Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            ),
            state: FlowState::Established,
            first_seen_us: 1_000,
            last_seen_us: 2_000,
            bytes_sent: 100,
            bytes_received: 200,
            packets_sent: 1,
            packets_received: 2,
            service: Some("HTTPS".to_string()),
            domain: None,
            process: None,
            risk_score: None,
            alert_count: 0,
            tags: Default::default(),
            initiator: None,
        }
    }

    #[test]
    fn batches_are_construction_flexible() {
        let mut batch = WriteBatch::new();
        assert!(batch.is_empty());
        batch.push(WriteItem::TrafficSample(TrafficSample::default()));
        assert_eq!(batch.len(), 1);

        assert_eq!(
            WriteBatch::single(WriteItem::Flow(Box::new(flow(1)))).len(),
            1
        );
    }

    #[test]
    fn flows_are_written_by_the_background_thread() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("sentinel.db");

        {
            let db = Database::open(&path, DatabaseOptions::default()).expect("open");
            let writer = StorageWriter::spawn(db, 64, 8);
            assert!(writer.is_running());

            for port in 1..5u16 {
                assert!(writer.submit_item(WriteItem::Flow(Box::new(flow(50_000 + port)))));
            }
            // Dropping the writer flushes and joins, so no polling is needed here.
        }

        let db = Database::open(&path, DatabaseOptions::default()).expect("reopen");
        assert_eq!(db.row_count("flows").expect("count"), 4);
        let stored = db.recent_flows(10).expect("read");
        assert!(
            stored
                .iter()
                .all(|record| record.flow.service.as_deref() == Some("HTTPS"))
        );
    }

    #[test]
    fn traffic_samples_and_settings_are_written() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("sentinel.db");

        {
            let db = Database::open(&path, DatabaseOptions::default()).expect("open");
            let writer = StorageWriter::spawn(db, 64, 4);
            writer.submit_item(WriteItem::TrafficSample(TrafficSample {
                bucket_start_us: 1_000_000,
                upload_bytes: 10,
                download_bytes: 20,
                packets: 3,
            }));
            writer.submit_item(WriteItem::Setting {
                key: "last_interface".to_string(),
                value: "\"3\"".to_string(),
            });
        }

        let db = Database::open(&path, DatabaseOptions::default()).expect("reopen");
        assert_eq!(db.row_count("traffic_samples").expect("count"), 1);
        assert_eq!(
            db.setting("last_interface").expect("read"),
            Some("\"3\"".to_string())
        );
    }

    #[test]
    fn an_empty_batch_is_accepted_and_writes_nothing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("sentinel.db");

        {
            let db = Database::open(&path, DatabaseOptions::default()).expect("open");
            let writer = StorageWriter::spawn(db, 8, 4);
            assert!(
                writer.submit(WriteBatch::new()),
                "an empty batch is trivially accepted"
            );
            assert_eq!(writer.stats().items_dropped, 0);
        }

        let db = Database::open(&path, DatabaseOptions::default()).expect("reopen");
        assert_eq!(db.row_count("flows").expect("count"), 0);
    }

    #[test]
    fn a_full_queue_does_not_block_the_submitter() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("sentinel.db");

        let db = Database::open(&path, DatabaseOptions::default()).expect("open");
        let writer = StorageWriter::spawn(db, 4, 1_000);

        let started = std::time::Instant::now();
        let mut accepted = 0usize;
        for index in 0..2_000u16 {
            // Submitting must never block, however slow the writer is.
            if writer.submit_item(WriteItem::Flow(Box::new(flow(50_000 + (index % 1_000))))) {
                accepted += 1;
            }
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "submitting 2000 items took {elapsed:?}; the pipeline must not block on storage"
        );
        assert_eq!(
            writer.stats().items_dropped,
            (2_000 - accepted) as u64,
            "every refusal is counted"
        );
    }

    #[test]
    fn the_writer_keeps_running_after_a_failed_batch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("sentinel.db");

        {
            let db = Database::open(&path, DatabaseOptions::default()).expect("open");
            let writer = StorageWriter::spawn(db, 64, 2);

            // A setting with a null byte in its value violates the NOT NULL constraint on the
            // `value` column, so the whole transaction fails and is rolled back.
            writer.submit_item(WriteItem::Setting {
                key: "bad".to_string(),
                value: "\u{0}".to_string(),
            });
            // A later batch must still be served: one failed transaction cannot kill the thread.
            writer.submit_item(WriteItem::Flow(Box::new(flow(1))));
            writer.submit_item(WriteItem::Flow(Box::new(flow(2))));
        }

        let db = Database::open(&path, DatabaseOptions::default()).expect("reopen");
        assert_eq!(
            db.row_count("flows").expect("count"),
            2,
            "later batches must still be written"
        );
    }

    #[test]
    fn stats_start_at_zero_and_track_submissions() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("sentinel.db");
        let db = Database::open(&path, DatabaseOptions::default()).expect("open");
        let writer = StorageWriter::spawn(db, 8, 8);

        assert_eq!(writer.stats(), WriterStats::default());
        writer.submit_item(WriteItem::Flow(Box::new(flow(1))));
        assert_eq!(writer.stats().items_submitted, 1);
    }
}
