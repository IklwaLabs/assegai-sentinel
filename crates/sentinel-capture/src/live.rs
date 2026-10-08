//! Live capture over `pcap` (Npcap on Windows, libpcap on Linux and macOS).
//!
//! # Threading
//!
//! `libpcap` reads block, so live capture runs on a **dedicated OS thread** rather than on a
//! Tokio task. The thread reads frames and pushes them into the bounded
//! [`PacketIngress`](crate::queue::PacketIngress); the engine drains the
//! [`PacketConsumer`](crate::queue::PacketConsumer). The capture thread is never blocked by a
//! slow consumer, and the queue's drop counter makes any loss visible instead of silent.
//!
//! # Filtering
//!
//! A BPF filter is compiled into the capture device, so unwanted traffic is discarded by the
//! kernel before it reaches user space. That is the difference between monitoring a busy
//! interface comfortably and not.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;

use bytes::Bytes;
use pcap::{Active, Capture, Device, IfFlags};
use sentinel_common::net::NetworkInterface;

use crate::error::{CaptureError, Result};
use crate::provider::{CaptureProvider, CaptureStats, RawPacket};
use crate::queue::{EnqueueResult, PacketConsumer, PacketIngress, QueueStats};

/// Tunables for a live capture session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCaptureConfig {
    /// Snapshot length in bytes. Larger values capture more per frame and cost more memory.
    pub snaplen: u32,
    /// Enable promiscuous mode, which sees traffic not addressed to this machine.
    pub promiscuous: bool,
    /// Read timeout in milliseconds, so a stop request is noticed promptly.
    pub read_timeout_ms: i32,
    /// Inactivity timeout in milliseconds after which the read loop gives up. A silent
    /// interface should end the session instead of running forever.
    pub idle_timeout_ms: u32,
    /// Optional BPF filter program, compiled into the device.
    pub filter: Option<String>,
}

impl Default for LiveCaptureConfig {
    fn default() -> Self {
        Self {
            // 65535 covers a full Ethernet frame including jumbo frames.
            snaplen: 65_535,
            promiscuous: false,
            read_timeout_ms: 250,
            // Ten minutes of continuous read timeouts.
            idle_timeout_ms: 600_000,
            filter: None,
        }
    }
}

/// Live capture from a network interface.
pub struct LiveCapture {
    config: LiveCaptureConfig,
    /// `None` while the reader thread owns the handle. The device cannot be reopened without
    /// stopping, so this doubles as the "is open" flag.
    handle: Option<Capture<Active>>,
    thread: Option<JoinHandle<CaptureStats>>,
    stop: Arc<AtomicBool>,
    interface: Option<String>,
    ingress: Arc<PacketIngress>,
    consumer: PacketConsumer,
    stats: Arc<LiveStats>,
}

/// Statistics the capture thread updates, readable from any thread.
#[derive(Debug, Default)]
struct LiveStats {
    received: AtomicU64,
    dropped: AtomicU64,
    interface_dropped: AtomicU64,
}

impl LiveStats {
    fn snapshot(&self) -> CaptureStats {
        CaptureStats {
            received: self.received.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            interface_dropped: self.interface_dropped.load(Ordering::Relaxed),
        }
    }
}

impl LiveCapture {
    /// Creates a live capture adapter over a bounded queue. No device is opened until
    /// [`CaptureProvider::open`].
    #[must_use]
    pub fn new(config: LiveCaptureConfig, queue_capacity: usize) -> Self {
        let (ingress, consumer) = crate::queue::channel(queue_capacity);
        Self {
            config,
            handle: None,
            thread: None,
            stop: Arc::new(AtomicBool::new(false)),
            interface: None,
            ingress: Arc::new(ingress),
            consumer,
            stats: Arc::new(LiveStats::default()),
        }
    }

    /// The consumer half of the ingress queue, drained by the engine.
    #[must_use]
    pub const fn consumer(&self) -> &PacketConsumer {
        &self.consumer
    }

    /// Ingress accounting, for the diagnostics panel.
    #[must_use]
    pub fn queue_stats(&self) -> QueueStats {
        self.ingress.stats()
    }

    /// Asks the capture thread to stop and waits for it to finish.
    ///
    /// Idempotent, and safe on an adapter that was never opened.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.handle = None;
    }

    /// True once the reader thread has exited on its own, for example because the device failed
    /// or the idle timeout elapsed.
    ///
    /// The engine polls this so an unexpected end of capture surfaces as a state change instead
    /// of a UI that silently stops updating.
    #[must_use]
    pub fn reader_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
    }

    /// Interface id currently being captured.
    #[must_use]
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }
}

impl CaptureProvider for LiveCapture {
    fn backend_name(&self) -> &'static str {
        "pcap"
    }

    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        // Delegated to the platform layer, the only place allowed to know the OS. This keeps
        // the list the user picks from identical to the list the backend can open.
        sentinel_platform::interfaces().map_err(|err| CaptureError::InterfaceUnavailable {
            interface: "any".to_string(),
            details: err.to_string(),
        })
    }

    fn open(&mut self, interface: &NetworkInterface) -> Result<()> {
        if self.handle.is_some() {
            return Ok(());
        }

        let capture = open_device(interface, &self.config)?;
        self.handle = Some(capture);
        self.interface = Some(interface.id.clone());
        self.stop.store(false, Ordering::Relaxed);
        self.spawn_reader();
        Ok(())
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        // Frames arrive through the queue, not a direct read, so one trait serves both live and
        // offline sources.
        Ok(self.consumer.try_next())
    }

    fn close(&mut self) -> Result<()> {
        self.stop();
        // Closing the queue lets the engine see end-of-stream, while packets already queued
        // remain readable so a clean shutdown does not discard them.
        if let Some(ingress) = Arc::get_mut(&mut self.ingress) {
            ingress.close();
        }
        self.interface = None;
        Ok(())
    }

    fn stats(&self) -> CaptureStats {
        self.stats.snapshot()
    }

    fn is_open(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        // A dropped adapter must not leave a thread reading from a device forever.
        self.stop();
    }
}

impl LiveCapture {
    /// Starts the reader thread, moving the open handle into it.
    ///
    /// The handle must move rather than be borrowed: the capture thread owns it for the life of
    /// the session, and a `Capture<Active>` is not `Sync`.
    fn spawn_reader(&mut self) {
        let Some(mut capture) = self.handle.take() else {
            return;
        };

        let ingress = Arc::clone(&self.ingress);
        let stop = Arc::clone(&self.stop);
        let stats = Arc::clone(&self.stats);
        let read_timeout_ms = self.config.read_timeout_ms;
        let idle_timeout_ms = self.config.idle_timeout_ms;
        let interface = self.interface.clone().unwrap_or_default();

        let spawned = std::thread::Builder::new()
            .name("sentinel-capture".to_string())
            .spawn(move || {
                let mut idle_ms = 0u32;

                while !stop.load(Ordering::Relaxed) {
                    match capture.next_packet() {
                        Ok(packet) => {
                            idle_ms = 0;
                            stats.received.fetch_add(1, Ordering::Relaxed);
                            let raw = RawPacket::new(
                                timestamp_from_parts(
                                    packet.header.ts.tv_sec,
                                    packet.header.ts.tv_usec,
                                ),
                                packet.header.caplen,
                                packet.header.len,
                                Bytes::copy_from_slice(packet.data),
                            );
                            if ingress.push(raw) == EnqueueResult::Dropped {
                                // Counted by the queue; logged at trace so overflow is
                                // visible in a log export without flooding it.
                                tracing::trace!(interface = %interface, "ingress queue full; frame dropped");
                            }
                        }
                        Err(err) => {
                            let message = err.to_string();
                            if is_read_timeout(&message) {
                                // A read timeout is the normal way a blocking read yields. It
                                // doubles as the idle check.
                                idle_ms = idle_ms.saturating_add(read_timeout_ms as u32);
                                if idle_ms >= idle_timeout_ms {
                                    tracing::debug!(interface = %interface, "capture idle timeout reached");
                                    break;
                                }
                                continue;
                            }
                            tracing::error!(interface = %interface, error = %message, "capture read failed");
                            break;
                        }
                    }
                }

                // Ask the driver for its counters before the handle is dropped.
                if let Ok(stat) = capture.stats() {
                    stats.dropped.store(u64::from(stat.dropped), Ordering::Relaxed);
                    stats.interface_dropped.store(u64::from(stat.if_dropped), Ordering::Relaxed);
                }
                stats.snapshot()
            });

        match spawned {
            Ok(thread) => self.thread = Some(thread),
            Err(err) => {
                // The device was moved into the failed spawn attempt, so it is gone and cannot
                // be restored. Without a reader thread the session cannot work, so the adapter
                // is marked stopped and the reason is logged rather than left looking open.
                tracing::error!(error = %err, "could not start the capture thread");
                self.stop.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Opens a pcap capture device with the configured options.
fn open_device(
    interface: &NetworkInterface,
    config: &LiveCaptureConfig,
) -> Result<Capture<Active>> {
    let device = Device::from(interface.id.as_str());
    let snaplen = i32::try_from(config.snaplen).unwrap_or(65_535);

    let mut capture = Capture::from_device(device)
        .map_err(|err| classify_pcap_error(err.to_string(), &interface.id))?
        .snaplen(snaplen)
        .promisc(config.promiscuous)
        .timeout(config.read_timeout_ms)
        .immediate_mode(true)
        .open()
        .map_err(|err| classify_pcap_error(err.to_string(), &interface.id))?;

    if let Some(program) = &config.filter {
        capture
            .filter(program, true)
            .map_err(|err| CaptureError::ReadFailed(format!("invalid capture filter: {err}")))?;
    }

    Ok(capture)
}

/// Converts a `timeval` pair to microseconds since the Unix epoch.
///
/// Signed components are used so a pre-epoch timestamp cannot wrap into a huge unsigned value.
///
/// The parameters are generic over `Into<i64>` rather than being declared `i64`, and that is
/// not decoration. `pcap` exposes them as `libc::time_t` and `libc::suseconds_t`, which are
/// `i32` under Windows and `i64` everywhere else. Widening the conversion to the callee means
/// the call site passes the field unchanged, so there is no `i64::from` for clippy to call a
/// useless conversion on Windows and no `as i64` for it to call an unnecessary cast on Linux.
///
/// An earlier version had the conversion at the call site and got this wrong twice in a row:
/// `i64::from` was correct only on Windows, and `as i64` was correct only on Linux. Each
/// version passed on the machine that produced it and failed on the other.
#[must_use]
pub(crate) fn timestamp_from_parts<S, U>(seconds: S, microseconds: U) -> u64
where
    S: Into<i64>,
    U: Into<i64>,
{
    let seconds: i64 = seconds.into();
    let microseconds: i64 = microseconds.into();
    let total = seconds
        .saturating_mul(1_000_000)
        .saturating_add(microseconds);
    u64::try_from(total).unwrap_or(0)
}

/// True when a read error is the normal timeout rather than a real failure.
fn is_read_timeout(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("timeout") || lower.contains("timed out")
}

/// Classifies a `pcap` error string into a typed error.
///
/// `pcap` surfaces failures as text, and the text is the only signal available. The patterns
/// checked here are the ones libpcap and Npcap actually produce; anything unrecognised becomes
/// an interface error with the original text preserved, so nothing is hidden.
fn classify_pcap_error(message: String, interface: &str) -> CaptureError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("not permitted")
        || lower.contains("access is denied")
        || lower.contains("requires elevation")
    {
        return CaptureError::PermissionDenied { details: message };
    }
    if lower.contains("no such device")
        || lower.contains("cannot find")
        || lower.contains("no device")
    {
        return CaptureError::InterfaceUnavailable {
            interface: interface.to_string(),
            details: message,
        };
    }
    if lower.contains("wpcap.dll")
        || lower.contains("no suitable pcap")
        || lower.contains("pcap not found")
    {
        return CaptureError::DriverUnavailable { details: message };
    }
    CaptureError::InterfaceUnavailable {
        interface: interface.to_string(),
        details: message,
    }
}

/// True when a device reports itself as up or running.
///
/// Used by the first-run experience to put plausible interfaces first in the picker.
#[must_use]
pub fn device_is_usable(flags: IfFlags) -> bool {
    flags.contains(IfFlags::UP) || flags.contains(IfFlags::RUNNING)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = LiveCaptureConfig::default();
        assert_eq!(
            config.snaplen, 65_535,
            "a full frame fits without truncation"
        );
        assert!(
            !config.promiscuous,
            "promiscuous mode is opt-in, not a surprise"
        );
        assert!(
            config.read_timeout_ms > 0,
            "a zero timeout would never return from a read"
        );
        assert!(config.idle_timeout_ms > 0);
        assert!(config.filter.is_none(), "no filter means no surprises");
    }

    #[test]
    fn timestamps_convert_from_seconds_and_microseconds() {
        assert_eq!(
            timestamp_from_parts(1_735_689_600, 500_000),
            1_735_689_600_500_000
        );
        assert_eq!(timestamp_from_parts(0, 0), 0);
    }

    #[test]
    fn timestamps_before_the_epoch_do_not_wrap() {
        assert_eq!(
            timestamp_from_parts(-1, 0),
            0,
            "a negative timestamp reads as zero, not u64::MAX"
        );
    }

    #[test]
    fn read_timeouts_are_distinguished_from_failures() {
        assert!(is_read_timeout("Packet buffer has overflowed, timeout"));
        assert!(is_read_timeout("Read timeout expired"));
        assert!(!is_read_timeout("Permission denied"));
    }

    #[test]
    fn errors_are_classified_by_their_message() {
        assert!(matches!(
            classify_pcap_error("Permission denied".to_string(), "eth0"),
            CaptureError::PermissionDenied { .. }
        ));
        assert!(matches!(
            classify_pcap_error("No such device exists".to_string(), "eth0"),
            CaptureError::InterfaceUnavailable { .. }
        ));
        assert!(matches!(
            classify_pcap_error("wpcap.dll not found".to_string(), "eth0"),
            CaptureError::DriverUnavailable { .. }
        ));
        // An unrecognised message is not discarded: it becomes an interface error that keeps
        // the original text.
        match classify_pcap_error("something unexpected".to_string(), "eth0") {
            CaptureError::InterfaceUnavailable { details, .. } => {
                assert_eq!(details, "something unexpected")
            }
            other => panic!("unexpected classification: {other:?}"),
        }
    }

    #[test]
    fn a_closed_adapter_is_inert() {
        let mut capture = LiveCapture::new(LiveCaptureConfig::default(), 16);
        assert!(!capture.is_open());
        assert_eq!(capture.backend_name(), "pcap");

        // Closing an adapter that was never opened must be safe: shutdown paths converge here.
        capture
            .close()
            .expect("closing an unopened adapter is safe");
        assert_eq!(capture.stats(), CaptureStats::default());
        assert!(capture.consumer().try_next().is_none());
    }

    #[test]
    fn opening_a_missing_interface_fails_cleanly() {
        let mut capture = LiveCapture::new(LiveCaptureConfig::default(), 64);

        // A synthetic interface that cannot exist: the attempt must fail with a typed error,
        // never a panic, and the adapter must remain usable afterwards.
        let missing = NetworkInterface::new("sentinel-does-not-exist", "Missing");
        let result = capture.open(&missing);
        assert!(result.is_err(), "a non-existent interface cannot be opened");
        assert!(!capture.is_open());
        assert!(capture.close().is_ok());
    }

    #[test]
    fn the_adapter_exposes_its_queue_and_consumer() {
        let mut capture = LiveCapture::new(LiveCaptureConfig::default(), 8);
        assert_eq!(capture.queue_stats().depth, 0);
        assert_eq!(capture.consumer().stats().accepted, 0);

        // A closed queue still lets the consumer read what it already holds.
        capture.close().expect("close");
        assert!(capture.consumer().try_next().is_none());
    }
}
