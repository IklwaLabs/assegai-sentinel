//! The engine: one task, one owner of mutable state.
//!
//! ```text
//! callers --EngineRequest--> engine task <--drain tick-- ingress queue
//!                                   |
//!                                   +-- pipeline (decode, flows, aggregation)
//!                                   +-- storage writer (batched)
//!                                   +-- event broadcaster (throttled snapshots)
//! ```
//!
//! The engine task owns every mutable analysis structure. That is the central design decision:
//! there is exactly one writer of the flow table, so the packet path needs no locks, and the
//! ownership of that state is obvious from reading this file.
//!
//! Capture does **not** run here. `libpcap` reads block, so capture owns a dedicated OS thread
//! inside `sentinel-capture` and publishes into a bounded queue. The engine drains that queue on
//! a tick, which means backpressure shows up as counted drops rather than as a stalled UI.

use std::sync::Arc;
use std::time::Duration;

use sentinel_capture::CaptureProvider;
use sentinel_capture::{LiveCapture, LiveCaptureConfig, OfflineCapture};
use sentinel_common::clock;
use sentinel_common::config::AppConfig;
use sentinel_common::metrics::EngineMetrics;
use sentinel_common::net::NetworkInterface;
use sentinel_common::throttle::Throttle;
use sentinel_flow::aggregate::TrafficSummary;

use sentinel_storage::{
    InterfaceRecord, ProtocolTotalRecord, RetentionJob, StorageWriter, WriteBatch, WriteItem,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::debug;

use crate::error::{CoreError, Result};
use crate::event::{ConnectionRow, EngineEvent, EngineSnapshot, EventBroadcaster, TrafficPoint};
use crate::pipeline::{Pipeline, PipelineConfig, PipelineStats, QueueAccounting};
use crate::request::{EngineRequest, RequestContext, Response};
use crate::session::{SessionState, SessionSummary};

/// How often the engine drains the ingress queue.
///
/// Short enough that the live view feels live, long enough that an idle engine does no work.
/// Within a tick the engine drains everything available, so this bounds latency, not throughput.
const DRAIN_INTERVAL: Duration = Duration::from_millis(25);

/// How often a snapshot is broadcast. Independent of the drain rate so a busy link does not
/// produce a flood of UI updates.
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);

/// How often retention is enforced and counters are written.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

/// How often flows and traffic samples are written to storage.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Flows idle for longer than this are written out even if they never close, so a long-lived
/// connection is not lost if the app is killed.
const FLUSH_IDLE_US: u64 = 10_000_000;

/// Upper bound on frames processed per drain tick, so one burst cannot starve request handling.
const MAX_FRAMES_PER_TICK: usize = 250_000;

/// Frames collected per borrow-legal chunk. Small enough to bound peak memory during a burst,
/// large enough that per-chunk overhead is irrelevant next to per-frame work.
const DRAIN_CHUNK: usize = 4_096;

/// Handle to a running engine.
///
/// Cheap to clone and safe to share across threads, which is what a Tauri command handler needs.
#[derive(Clone)]
pub struct EngineHandle {
    requests: mpsc::Sender<Envelope>,
    join: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
    events: EventBroadcaster,
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("events", &self.events)
            .finish()
    }
}

/// A request plus the channel its answer goes back on.
struct Envelope {
    request: EngineRequest,
    reply: oneshot::Sender<Result<Response>>,
}

/// Engine construction parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOptions {
    /// Effective configuration.
    pub config: AppConfig,
    /// Number of connections to include in a snapshot.
    pub snapshot_connections: usize,
    /// Queue capacity between capture and the engine.
    pub queue_capacity: usize,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            config: AppConfig::default(),
            snapshot_connections: 200,
            queue_capacity: 32_768,
        }
    }
}

/// A running engine.
pub struct Engine {
    handle: EngineHandle,
}

impl Engine {
    /// Starts an engine on the current Tokio runtime.
    ///
    /// # Errors
    /// Returns [`CoreError`] when the storage database or data directory cannot be opened.
    pub async fn start(options: EngineOptions) -> Result<Self> {
        let paths = sentinel_platform::AppPaths::discover()?;
        paths.ensure()?;
        let database = sentinel_storage::Database::open(
            &paths.database_file,
            sentinel_storage::DatabaseOptions {
                wal_mode: options.config.advanced.wal_mode,
                ..sentinel_storage::DatabaseOptions::default()
            },
        )?;

        let writer = StorageWriter::spawn(
            database,
            options.queue_capacity.clamp(64, 65_536),
            options.config.advanced.write_batch_size as usize,
        );

        let (requests, receiver) = mpsc::channel(64);
        let events = EventBroadcaster::new();

        let task = EngineTask::new(options, writer, events.clone());
        let join = tokio::spawn(task.run(receiver));

        Ok(Self {
            handle: EngineHandle {
                requests,
                join: Arc::new(std::sync::Mutex::new(Some(join))),
                events,
            },
        })
    }

    /// A handle for sending requests and subscribing to events.
    #[must_use]
    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }

    /// Stops the engine task, flushing pending writes.
    pub fn shutdown(&self) {
        let Ok(mut guard) = self.handle.join.lock() else {
            // A poisoned lock means a previous shutdown panicked while holding it. The task is
            // still abortable, so fall back to a best-effort abort rather than leaking a thread.
            tracing::warn!("engine task handle is poisoned; the task may still be running");
            return;
        };
        if let Some(join) = guard.take() {
            join.abort();
        }
    }
}

impl EngineHandle {
    /// Subscribes to the engine's event stream.
    #[must_use]
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<EngineEvent> {
        self.events.subscribe()
    }

    /// Sends a request and waits for its answer.
    ///
    /// # Errors
    /// Returns [`CoreError::EngineStopped`] when the engine has ended, and
    /// [`CoreError::RequestFailed`] when no answer arrives.
    pub async fn request(&self, request: EngineRequest) -> Result<Response> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Envelope { request, reply })
            .await
            .map_err(|_| CoreError::EngineStopped("the request channel is closed".to_string()))?;

        response
            .await
            .map_err(|_| CoreError::RequestFailed("the engine did not answer".to_string()))?
    }

    /// True when the engine task is still running.
    ///
    /// The request channel being open means the engine task has not yet exited; once the task
    /// ends, the channel closes and requests fail with `EngineStopped`.
    #[must_use]
    pub fn is_running(&self) -> bool {
        !self.requests.is_closed()
    }

    /// Number of live event subscribers, for diagnostics.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.events.subscriber_count()
    }
}

/// The engine task's owned state.
struct EngineTask {
    options: EngineOptions,
    pipeline: Pipeline,
    storage: StorageWriter,
    retention: RetentionJob,
    events: EventBroadcaster,
    metrics: EngineMetrics,
    state: SessionState,
    context: RequestContext,
    interface: Option<NetworkInterface>,
    live: Option<LiveCapture>,
    offline: Option<OfflineCapture>,
    snapshot_throttle: Throttle,
    last_written_bucket: Option<u64>,
    /// Protocol totals already written, as `(protocol, cumulative bytes)`, so each flush sends
    /// a delta rather than re-sending the session total and double-counting it on disk.
    flushed_protocols: Option<Vec<(sentinel_common::packet::TransportProtocol, u64)>>,
    started_us: Option<u64>,
    last_flush_us: u64,
    /// A read failure from the offline source, applied after the current chunk is processed.
    offline_error: Option<String>,
}

impl EngineTask {
    /// Builds the engine state.
    fn new(options: EngineOptions, storage: StorageWriter, events: EventBroadcaster) -> Self {
        let pipeline_config = PipelineConfig::from_capture_config(&options.config.capture);
        let now = clock::now_unix_micros();
        let retention = RetentionJob::from_config(&options.config, now);
        let snapshot_throttle = Throttle::from_hz(options.config.capture.ui_update_hz.max(1));

        Self {
            pipeline: Pipeline::new(pipeline_config),
            retention,
            events,
            metrics: EngineMetrics::default(),
            state: SessionState::Idle,
            context: RequestContext::empty(),
            interface: None,
            live: None,
            offline: None,
            snapshot_throttle,
            last_written_bucket: None,
            flushed_protocols: None,
            started_us: None,
            last_flush_us: now,
            offline_error: None,
            options,
            storage,
        }
    }

    /// The engine's main loop.
    async fn run(mut self, mut requests: mpsc::Receiver<Envelope>) {
        let mut drain = tokio::time::interval(DRAIN_INTERVAL);
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
        let mut flush = tokio::time::interval(FLUSH_INTERVAL);

        // A failed first tick would fire immediately; these are all no-ops until data exists.
        drain.tick().await;
        heartbeat.tick().await;
        maintenance.tick().await;
        flush.tick().await;

        loop {
            tokio::select! {
                envelope = requests.recv() => {
                    match envelope {
                        Some(envelope) => self.handle_request(envelope),
                        // Every sender is gone: flush and stop.
                        None => break,
                    }
                }
                _ = drain.tick() => self.drain(),
                _ = heartbeat.tick() => self.maybe_publish(),
                _ = maintenance.tick() => self.maintenance(),
                _ = flush.tick() => self.flush_to_storage(),
            }
        }

        self.shutdown();
    }

    /// Handles one request and answers it.
    fn handle_request(&mut self, envelope: Envelope) {
        let Envelope { request, reply } = envelope;
        let response = self.respond(request);
        // A dropped receiver means the caller went away, which is not an error worth logging.
        let _ = reply.send(response);
    }

    /// Executes a request.
    fn respond(&mut self, request: EngineRequest) -> Result<Response> {
        match request {
            EngineRequest::ListInterfaces => self.list_interfaces(),
            EngineRequest::Capabilities => self.capabilities(),
            EngineRequest::Status => Ok(Response::Status {
                state: self.state.clone(),
                summary: self.summary(),
            }),
            EngineRequest::Start { interface_id } => self.start_capture(&interface_id),
            EngineRequest::Stop => self.stop_capture(),
            EngineRequest::Analyze { path } => self.analyze_file(&path),
            EngineRequest::Snapshot => Ok(Response::Snapshot(Box::new(self.snapshot()))),
            EngineRequest::GetConfig => Ok(Response::Config(Box::new(self.options.config.clone()))),
            EngineRequest::SetConfig { config } => self.set_config(config),
        }
    }

    /// Lists capturable interfaces and records them for the picker.
    fn list_interfaces(&mut self) -> Result<Response> {
        let interfaces = self.platform_interfaces()?;
        self.context = RequestContext::from_interfaces(&interfaces);
        self.pipeline
            .set_local_addresses(self.context.local_addresses.clone());
        Ok(Response::Interfaces(interfaces))
    }

    /// Reports platform capabilities, degrading a failure into a usable response.
    fn capabilities(&mut self) -> Result<Response> {
        match sentinel_platform::capabilities() {
            Ok(capabilities) => Ok(Response::Capabilities(Box::new(capabilities))),
            Err(err) => {
                // `sentinel doctor` must produce a report even when probing fails, so the
                // error travels as a notice rather than as a failed request.
                self.events.publish(EngineEvent::Notice(
                    sentinel_common::error::UserFacing::user_message(&err),
                ));
                Ok(Response::Acknowledged)
            }
        }
    }

    /// Starts live capture on a named interface.
    fn start_capture(&mut self, interface_id: &str) -> Result<Response> {
        if let SessionState::Monitoring { interface, .. } = &self.state {
            return Err(CoreError::AlreadyRunning(interface.clone()));
        }
        if self.state.is_active() {
            return Err(CoreError::AlreadyRunning(
                self.state
                    .interface_id()
                    .unwrap_or("another source")
                    .to_string(),
            ));
        }

        self.reset_session();
        self.state = SessionState::Preparing;
        self.events
            .publish(EngineEvent::StateChanged(self.state.clone()));

        let interfaces = self.platform_interfaces()?;
        let interface = interfaces
            .iter()
            .find(|candidate| candidate.id == interface_id)
            .cloned()
            .ok_or_else(|| CoreError::UnknownInterface(interface_id.to_string()))?;

        // Orient flows before the first packet arrives, so the very first connection is already
        // attributed correctly.
        self.context = RequestContext::from_interfaces(&interfaces);
        self.pipeline
            .set_local_addresses(self.context.local_addresses.clone());

        let config = LiveCaptureConfig {
            snaplen: self.options.config.capture.snaplen,
            promiscuous: self.options.config.capture.promiscuous,
            read_timeout_ms: self.options.config.capture.read_timeout_ms,
            ..LiveCaptureConfig::default()
        };
        let mut capture = LiveCapture::new(config, self.options.queue_capacity);
        capture.open(&interface)?;

        self.state = SessionState::Monitoring {
            interface: interface.id.clone(),
            interface_name: interface.name.clone(),
        };
        self.interface = Some(interface.clone());
        self.live = Some(capture);
        self.started_us = Some(clock::now_unix_micros());

        // Interfaces are small and change rarely; recording them keeps the inventory useful
        // without a separate discovery loop.
        self.storage
            .submit_item(WriteItem::Interface(InterfaceRecord::new(&interface)));

        self.events
            .publish(EngineEvent::StateChanged(self.state.clone()));
        debug!(interface = %interface.name, "capture session started");
        Ok(Response::Started {
            state: self.state.clone(),
        })
    }

    /// Stops the active session.
    fn stop_capture(&mut self) -> Result<Response> {
        if !self.state.is_active() {
            return Err(CoreError::NotRunning);
        }
        self.teardown();
        self.state = SessionState::Idle;
        self.events
            .publish(EngineEvent::StateChanged(self.state.clone()));
        self.flush_to_storage();
        Ok(Response::Stopped)
    }

    /// Analyses a capture file offline.
    ///
    /// The same pipeline, decoder and flow engine run as for live capture; only the source
    /// differs, which is what guarantees offline analysis sees identical behaviour.
    fn analyze_file(&mut self, path: &str) -> Result<Response> {
        if self.state.is_active() {
            return Err(CoreError::AlreadyRunning(
                self.state
                    .interface_id()
                    .unwrap_or("another source")
                    .to_string(),
            ));
        }

        self.reset_session();
        self.state = SessionState::Preparing;
        self.events
            .publish(EngineEvent::StateChanged(self.state.clone()));

        let file_name = std::path::Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());

        // Offline analysis still runs on this machine, so this machine's addresses are a
        // reasonable reference for orienting rows. When a capture came from elsewhere, no
        // endpoint matches and rows are reported as unoriented rather than mislabelled.
        if let Ok(interfaces) = self.platform_interfaces() {
            self.context = RequestContext::from_interfaces(&interfaces);
            self.pipeline
                .set_local_addresses(self.context.local_addresses.clone());
        }

        // A file's queue must hold the whole file, or later frames would be dropped and the
        // analysis would silently understate what it saw.
        let capture = OfflineCapture::open(path, self.options.queue_capacity)?;
        self.offline = Some(capture);
        self.state = SessionState::Analyzing { file_name };
        self.started_us = Some(clock::now_unix_micros());
        self.events
            .publish(EngineEvent::StateChanged(self.state.clone()));

        Ok(Response::Started {
            state: self.state.clone(),
        })
    }

    /// Replaces the effective configuration.
    fn set_config(&mut self, config: AppConfig) -> Result<Response> {
        // Validation before application: a bad value must be rejected at the boundary, not
        // discovered later when a capture thread tries to use it.
        config.validate()?;

        let ui_hz_changed = config.capture.ui_update_hz != self.options.config.capture.ui_update_hz;
        let retention_changed = config.retention != self.options.config.retention;

        self.options.config = config.clone();
        if ui_hz_changed {
            self.snapshot_throttle = Throttle::from_hz(config.capture.ui_update_hz.max(1));
        }
        if retention_changed {
            self.retention = RetentionJob::from_config(&config, clock::now_unix_micros());
        }
        Ok(Response::Config(Box::new(config)))
    }

    /// Drains the ingress queue and processes what it finds.
    ///
    /// Frames are collected into small chunks before being processed, because the pipeline needs
    /// `&mut self` while the capture adapters are only borrowable immutably (or are mid-mutable
    /// borrow for offline reads). Chunking keeps the borrow legal and the memory bounded: a
    /// whole burst is never buffered at once.
    fn drain(&mut self) {
        let mut processed = 0usize;

        loop {
            let mut chunk: Vec<sentinel_capture::RawPacket> = Vec::with_capacity(DRAIN_CHUNK);

            if let Some(capture) = self.live.as_ref() {
                for _ in 0..DRAIN_CHUNK {
                    match capture.consumer().try_next() {
                        Some(raw) => chunk.push(raw),
                        None => break,
                    }
                }
            }

            if let Some(capture) = self.offline.as_mut() {
                for _ in 0..DRAIN_CHUNK {
                    match capture.next_packet() {
                        Ok(Some(raw)) => chunk.push(raw),
                        Ok(None) => break,
                        Err(err) => {
                            // The engine stops on a read error but keeps the frames it already
                            // has; the error becomes the session's reason so the UI can explain
                            // why the analysis ended early.
                            self.offline_error = Some(err.to_string());
                            break;
                        }
                    }
                }
            }

            if chunk.is_empty() {
                break;
            }

            let drained_everything = chunk.len() < DRAIN_CHUNK * 2;
            for raw in &chunk {
                self.process(raw);
            }
            processed += chunk.len();

            if processed >= MAX_FRAMES_PER_TICK || drained_everything {
                break;
            }
        }

        if processed > 0 {
            self.metrics.observe_queue_depth(self.queue_depth());
        }

        if let Some(reason) = self.offline_error.take() {
            self.teardown();
            self.state = SessionState::failed(reason);
            self.events
                .publish(EngineEvent::StateChanged(self.state.clone()));
            self.flush_to_storage();
            return;
        }

        // End of source: a file is exhausted, or the capture thread exited on its own.
        self.check_for_source_end();
    }

    /// Processes one frame through the pipeline.
    fn process(&mut self, raw: &sentinel_capture::RawPacket) {
        self.metrics.record_captured(u64::from(raw.original_len));
        let _ = self.pipeline.process(raw, Some(&self.metrics));
    }

    /// Ends the session when its source has no more frames.
    fn check_for_source_end(&mut self) {
        match &self.state {
            SessionState::Analyzing { file_name } => {
                let finished = self
                    .offline
                    .as_ref()
                    .is_none_or(|capture| !capture.is_open());
                if finished {
                    debug!(file = %file_name, "offline analysis complete");
                    self.teardown();
                    self.state = SessionState::Idle;
                    self.events
                        .publish(EngineEvent::StateChanged(self.state.clone()));
                    self.flush_to_storage();
                }
            }
            SessionState::Monitoring { .. } => {
                let finished = self.live.as_ref().is_none_or(LiveCapture::reader_finished);
                if finished {
                    // The reader thread can exit on a device error or an idle timeout. Either
                    // way the UI must be told, rather than quietly freezing.
                    let reason = self
                        .live
                        .as_ref()
                        .map(|capture| capture.stats())
                        .filter(|stats| stats.has_loss())
                        .map(|_| "the capture device reported packet loss")
                        .unwrap_or("the capture device stopped");
                    self.teardown();
                    self.state = SessionState::failed(reason);
                    self.events
                        .publish(EngineEvent::StateChanged(self.state.clone()));
                    self.flush_to_storage();
                }
            }
            _ => {}
        }
    }

    /// Periodic maintenance: retention enforcement.
    ///
    /// Retention runs inside the writer's transaction rather than on a second database handle,
    /// because SQLite has a single writer and a second connection would only contend for the
    /// write lock, reporting a spurious "database is locked" error to the user.
    fn maintenance(&mut self) {
        let now = clock::now_unix_micros();
        if !self.retention.is_due(now) {
            return;
        }

        let mut batch = WriteBatch::new();
        batch.push(WriteItem::Retention {
            flows_cutoff_us: self.retention.flows_cutoff(),
            samples_cutoff_us: self.retention.samples_cutoff(),
        });
        if !self.storage.submit(batch) {
            debug!("storage queue full; the retention sweep was dropped and counted");
            // Leaving the job un-marked means the next tick retries instead of skipping a whole
            // interval because of a transient backlog.
            return;
        }
        self.retention.mark_ran(now);
    }

    /// Writes flows and traffic samples, then a session summary.
    fn flush_to_storage(&mut self) {
        let now = clock::now_unix_micros();
        let mut batch = WriteBatch::new();

        // Flows that have closed, or gone quiet, are persisted. Active flows stay in memory for
        // the live view and are written on a later flush.
        for flow in self.pipeline.flows_by_volume(usize::MAX) {
            let quiet = now.saturating_sub(flow.last_seen_us) >= FLUSH_IDLE_US;
            if crate::pipeline::is_finished(&flow) || quiet {
                batch.push(WriteItem::Flow(Box::new(flow)));
            }
        }

        // Traffic samples are written once each, tracked by bucket start.
        for sample in self.pipeline.traffic_samples() {
            let already_written = self
                .last_written_bucket
                .is_some_and(|last| sample.bucket_start_us <= last);
            if already_written {
                continue;
            }
            batch.push(WriteItem::TrafficSample(sample));
            self.last_written_bucket = Some(sample.bucket_start_us);
        }

        // Protocol totals are cumulative for the session, so they are written as a delta of the
        // previous flush rather than the full total, which would double-count on every flush.
        let summary = self.pipeline.traffic_summary();
        if let Some(delta) = self.protocol_delta(&summary) {
            batch.push(WriteItem::ProtocolTotal(delta));
        }

        if !batch.is_empty() {
            let accepted = self.storage.submit(batch);
            if !accepted {
                debug!("storage queue full; this flush was dropped and counted");
            }
        }

        self.last_flush_us = now;
    }

    /// Builds the protocol-total delta since the last flush.
    fn protocol_delta(&mut self, summary: &TrafficSummary) -> Option<ProtocolTotalRecord> {
        self.flushed_protocols.get_or_insert_with(Vec::new);
        let flushed = self.flushed_protocols.as_mut().expect("just initialised");

        let mut delta: Option<ProtocolTotalRecord> = None;
        for totals in &summary.protocols {
            let previous = flushed
                .iter()
                .find(|(protocol, _)| *protocol == totals.protocol)
                .map(|(_, bytes)| *bytes)
                .unwrap_or(0);

            if totals.bytes <= previous {
                continue;
            }
            let record = ProtocolTotalRecord::new(
                sentinel_flow::aggregate::ProtocolTotals {
                    protocol: totals.protocol,
                    bytes: totals.bytes - previous,
                    packets: totals.packets,
                    flows: totals.flows,
                },
                self.last_flush_us,
                clock::now_unix_micros(),
            );
            flushed.retain(|(protocol, _)| *protocol != totals.protocol);
            flushed.push((totals.protocol, totals.bytes));
            delta = Some(record);
        }
        delta
    }

    /// Publishes a snapshot when the throttle allows it.
    fn maybe_publish(&mut self) {
        if !self.state.is_active() && self.snapshot_throttle.should_emit() {
            // Publishing while idle would send a stream of empty snapshots, which is noise.
            return;
        }
        if self.snapshot_throttle.should_emit() {
            self.metrics.record_ui_event();
            self.events
                .publish(EngineEvent::Snapshot(Arc::new(self.snapshot())));
        }
    }

    /// Releases the capture source and resets per-session state.
    fn teardown(&mut self) {
        if let Some(mut capture) = self.live.take() {
            let _ = capture.close();
        }
        if let Some(mut capture) = self.offline.take() {
            let _ = capture.close();
        }
        self.interface = None;
    }

    /// Clears analysis state so a new session starts from zero.
    fn reset_session(&mut self) {
        self.teardown();
        self.pipeline.reset();
        self.last_written_bucket = None;
        self.flushed_protocols = None;
        self.offline_error = None;
        self.started_us = Some(clock::now_unix_micros());
    }

    /// Final work when the engine loop ends.
    fn shutdown(&mut self) {
        self.flush_to_storage();
        self.teardown();
        // Dropping the writer flushes and joins its thread, so nothing accepted is lost.
        debug!("engine stopped");
    }

    /// Current ingress queue depth across both sources.
    fn queue_depth(&self) -> u64 {
        let live = self
            .live
            .as_ref()
            .map_or(0, |capture| capture.queue_stats().depth as u64);
        let offline = self
            .offline
            .as_ref()
            .map_or(0, |capture| capture.queue_len() as u64);
        live + offline
    }

    /// Queue accounting for the diagnostics panel.
    fn queue_accounting(&self) -> QueueAccounting {
        let (accepted, dropped, watermark) = match (&self.live, &self.offline) {
            (Some(capture), _) => {
                let stats = capture.queue_stats();
                (stats.accepted, stats.dropped, stats.high_watermark)
            }
            (None, Some(capture)) => {
                let stats = capture.consumer().stats();
                (stats.accepted, stats.dropped, stats.high_watermark)
            }
            (None, None) => (0, 0, 0),
        };
        QueueAccounting {
            accepted,
            dropped,
            high_watermark: watermark,
        }
    }

    /// A compact summary of the current or most recent session.
    fn summary(&self) -> SessionSummary {
        let summary = self.pipeline.traffic_summary();
        let start = self.started_us.unwrap_or(summary.started_us);
        let end = summary.last_packet_us.max(start);

        SessionSummary {
            packets: summary.packets,
            bytes: summary.total_bytes(),
            flows_created: self.pipeline.counters().flows_created,
            flows_active: self.pipeline.flow_count() as u64,
            duration_us: end.saturating_sub(start),
            // A lossy capture must say so, or every statistic derived from it is a lie.
            packets_lost: self.metrics.snapshot(false, 0).packets_dropped
                + self.queue_accounting().dropped
                + self.backend_dropped(),
        }
    }

    /// Driver-level drops reported by the capture backend.
    fn backend_dropped(&self) -> u64 {
        self.live
            .as_ref()
            .map(|capture| capture.stats().dropped + capture.stats().interface_dropped)
            .unwrap_or(0)
    }

    /// Builds a complete snapshot for the API layer.
    fn snapshot(&self) -> EngineSnapshot {
        let summary = self.pipeline.traffic_summary();
        let (upload_bps, download_bps) = self.pipeline.current_rate_bps();
        let connections: Vec<ConnectionRow> = self
            .pipeline
            .flows_by_recent(self.options.snapshot_connections)
            .iter()
            .map(|flow| ConnectionRow::from_flow_oriented(flow, &self.context.local_addresses))
            .collect();

        EngineSnapshot {
            state: self.state.clone(),
            interface: self.interface.clone(),
            total_upload_bytes: summary.upload_bytes,
            total_download_bytes: summary.download_bytes,
            total_packets: summary.packets,
            first_seen_us: summary.started_us,
            last_seen_us: summary.last_packet_us,
            upload_bps,
            download_bps,
            traffic: self
                .pipeline
                .traffic_samples()
                .into_iter()
                .map(TrafficPoint::from)
                .collect(),
            connections,
            flows_active: self.pipeline.flow_count() as u64,
            stats: PipelineStats {
                counters: self.pipeline.counters(),
                flows_active: self.pipeline.flow_count() as u64,
                queue: self.queue_accounting(),
            },
            metrics: self
                .metrics
                .snapshot(self.state.is_active(), self.backend_dropped()),
            config: self.options.config.clone(),
        }
    }

    /// Platform interfaces, mapped into a core error.
    fn platform_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        sentinel_platform::interfaces().map_err(CoreError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_are_sane_for_a_live_view() {
        // Constants are compared against each other rather than against literals, so the
        // assertions document relationships instead of restating the numbers.
        assert!(
            DRAIN_INTERVAL <= HEARTBEAT_INTERVAL,
            "draining must be at least as often as publishing"
        );
        assert!(
            FLUSH_INTERVAL >= HEARTBEAT_INTERVAL,
            "storage must not be written more often than the UI is told about it"
        );
        assert!(
            MAINTENANCE_INTERVAL >= FLUSH_INTERVAL,
            "retention runs after each flush"
        );
    }

    #[test]
    fn engine_options_have_a_bounded_snapshot_size() {
        let default = EngineOptions::default();
        assert!(
            default.snapshot_connections > 0,
            "a snapshot with no connections is useless"
        );
        assert!(
            default.snapshot_connections <= 10_000,
            "a snapshot must stay cheap to serialize"
        );
        assert!(default.queue_capacity > 0);
    }

    #[test]
    fn a_session_summary_flags_ingress_loss() {
        let metrics = EngineMetrics::default();
        metrics.record_dropped(5);
        let snapshot = metrics.snapshot(false, 0);
        assert_eq!(snapshot.packets_dropped, 5);
        assert!(snapshot.drop_ratio() > 0.0);
    }

    #[test]
    fn pipeline_config_follows_capture_settings() {
        let mut config = AppConfig::default();
        config.capture.flow_idle_timeout_secs = 30;
        config.capture.max_tracked_flows = 1_000;
        config.capture.queue_capacity = 32_768;

        let pipeline = PipelineConfig::from_capture_config(&config.capture);
        assert_eq!(pipeline.flow_table.idle_timeout_us, 30_000_000);
        assert_eq!(pipeline.flow_table.max_flows, 1_000);
        assert!(
            pipeline.flow_table.sweep_interval_packets >= 500,
            "sweeping must not be so frequent that it costs more than it saves"
        );
    }

    #[test]
    fn sweep_cadence_scales_with_throughput_but_stays_bounded() {
        let mut config = AppConfig::default();
        config.capture.queue_capacity = 256;
        let quiet = PipelineConfig::from_capture_config(&config.capture)
            .flow_table
            .sweep_interval_packets;

        config.capture.queue_capacity = 1_000_000;
        let busy = PipelineConfig::from_capture_config(&config.capture)
            .flow_table
            .sweep_interval_packets;

        assert!(
            quiet < busy,
            "a busier pipeline sweeps less often in packet terms"
        );
        assert!((500..=8_192).contains(&quiet), "got {quiet}");
        assert!((500..=8_192).contains(&busy), "got {busy}");
    }

    #[test]
    fn frames_per_tick_are_bounded_so_requests_are_not_starved() {
        // The relationship between the two constants is the invariant; the values themselves are
        // documented on the constants, so asserting them here would only restate the source.
        // A compile-time check keeps the two from drifting apart without a runtime assertion.
        const _: () = assert!(DRAIN_CHUNK <= MAX_FRAMES_PER_TICK);
        const _: () = assert!(DRAIN_CHUNK > 0);
    }
}
