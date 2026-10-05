//! The `CaptureProvider` trait and the raw packet type.
//!
//! One trait, several implementations. Business logic depends on this abstraction and never
//! on `pcap`, on `VpnService`, or on the operating system.

use bytes::Bytes;
use sentinel_common::net::NetworkInterface;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A frame as delivered by a capture source, before decoding.
///
/// The payload is a [`Bytes`] handle so a source can share buffers without copying. It is
/// dropped as soon as the frame has been decoded, which is why nothing downstream retains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    /// Capture timestamp in microseconds since the Unix epoch.
    pub timestamp_us: u64,
    /// Bytes actually present.
    pub captured_len: u32,
    /// Bytes on the wire; larger than `captured_len` when the frame was truncated.
    pub original_len: u32,
    /// Frame bytes.
    pub data: Bytes,
}

impl RawPacket {
    /// Wraps a frame buffer.
    #[must_use]
    pub fn new(timestamp_us: u64, captured_len: u32, original_len: u32, data: Bytes) -> Self {
        Self {
            timestamp_us,
            captured_len,
            original_len,
            data,
        }
    }

    /// True when the frame was cut short by the snapshot length.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.captured_len < self.original_len
    }
}

/// Driver-level statistics, where the capture backend exposes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStats {
    /// Frames handed to Sentinel.
    pub received: u64,
    /// Frames the driver dropped because its buffer was full.
    pub dropped: u64,
    /// Frames the network interface itself dropped.
    pub interface_dropped: u64,
}

impl CaptureStats {
    /// True when the driver reported any loss.
    #[must_use]
    pub const fn has_loss(&self) -> bool {
        self.dropped > 0 || self.interface_dropped > 0
    }
}

/// A source of raw frames.
///
/// Implementations are responsible for their own threading model. The live adapter runs a
/// dedicated OS thread because `libpcap` reads block; the offline adapter reads on the calling
/// thread because a file read is already fast and non-blocking in practice.
pub trait CaptureProvider: Send {
    /// Human-readable name of the backend, for diagnostics.
    fn backend_name(&self) -> &'static str;

    /// Lists interfaces this provider can open.
    ///
    /// # Errors
    /// Returns [`crate::CaptureError`] when enumeration is unavailable.
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>>;

    /// Starts capturing from `interface`.
    ///
    /// # Errors
    /// Returns [`crate::CaptureError`] when the interface cannot be opened.
    fn open(&mut self, interface: &NetworkInterface) -> Result<()>;

    /// Reads the next frame, or `None` when the source is exhausted or stopped.
    ///
    /// # Errors
    /// Returns [`crate::CaptureError`] for read failures that are not a clean stop.
    fn next_packet(&mut self) -> Result<Option<RawPacket>>;

    /// Stops capturing and releases the device.
    ///
    /// Must be safe to call more than once and safe to call on a provider that was never
    /// opened, because shutdown paths converge here.
    fn close(&mut self) -> Result<()>;

    /// Driver-level statistics for the open device.
    fn stats(&self) -> CaptureStats;

    /// True while the provider is open.
    fn is_open(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_packets_report_truncation() {
        let whole = RawPacket::new(0, 60, 60, Bytes::from_static(&[0u8; 4]));
        assert!(!whole.is_truncated());

        let cut = RawPacket::new(0, 20, 60, Bytes::from_static(&[0u8; 4]));
        assert!(cut.is_truncated());
    }

    #[test]
    fn capture_stats_detect_loss() {
        assert!(!CaptureStats::default().has_loss());
        assert!(
            CaptureStats {
                dropped: 1,
                ..CaptureStats::default()
            }
            .has_loss()
        );
        assert!(
            CaptureStats {
                interface_dropped: 1,
                ..CaptureStats::default()
            }
            .has_loss()
        );
    }
}
