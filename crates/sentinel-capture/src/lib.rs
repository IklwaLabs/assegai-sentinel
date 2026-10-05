//! Packet capture for Iklwa Sentinel.
//!
//! This crate owns the boundary between the operating system and Sentinel's analysis core. It
//! produces [`RawPacket`] frames and knows nothing about flows, detection or storage.
//!
//! Sources:
//! - [`LiveCapture`]: Npcap/libpcap capture on a dedicated OS thread.
//! - [`OfflineCapture`]: classic PCAP files, for investigation and testing.
//!
//! Both implement [`CaptureProvider`], so a single downstream pipeline serves live and offline
//! analysis. Between a source and that pipeline sits a bounded queue, created by [`channel`]:
//! a [`PacketIngress`] producer half shared with the capture thread and a [`PacketConsumer`]
//! consumer half owned by the engine. Backpressure is explicit and every dropped frame is
//! counted.

pub mod error;
pub mod live;
pub mod offline;
pub mod provider;
pub mod queue;

pub use error::{CaptureError, Result};
pub use live::{LiveCapture, LiveCaptureConfig};
pub use offline::{OfflineCapture, OfflineSummary};
pub use provider::{CaptureProvider, CaptureStats, RawPacket};
pub use queue::{EnqueueResult, PacketConsumer, PacketIngress, QueueStats, channel};
