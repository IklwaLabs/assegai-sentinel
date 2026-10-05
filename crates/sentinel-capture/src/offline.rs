//! Offline PCAP analysis source.
//!
//! Reuses the same [`CaptureProvider`] trait as live capture, which is what guarantees offline
//! analysis runs through the identical decoder, flow engine and (later) detection code. There
//! is no second analysis path to keep in sync.

use std::path::Path;

use bytes::Bytes;
use sentinel_parser::pcap::PcapReader;

use crate::error::Result;
use crate::provider::{CaptureProvider, CaptureStats, RawPacket};
use crate::queue::PacketConsumer;

/// A capture file being read.
pub struct OfflineCapture {
    reader: Option<PcapReader<std::fs::File>>,
    consumer: PacketConsumer,
    ingress: crate::queue::PacketIngress,
    seen: u64,
    exhausted: bool,
    link_type: u32,
}

/// Summary of an offline capture, produced once the file has been read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineSummary {
    /// Frames read from the file.
    pub packets: u64,
    /// Link-layer type declared by the file.
    pub link_type: u32,
    /// First frame timestamp in microseconds since the Unix epoch.
    pub first_seen_us: u64,
    /// Last frame timestamp.
    pub last_seen_us: u64,
    /// Frames that could not be read because the file ended mid-record.
    pub truncated: bool,
}

impl OfflineSummary {
    /// Capture span in microseconds.
    #[must_use]
    pub const fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }
}

impl OfflineCapture {
    /// Opens a capture file.
    ///
    /// # Errors
    /// Returns [`CaptureError::File`] when the file is missing, is PCAPNG, or has an
    /// unrecognized magic number.
    pub fn open(path: impl AsRef<Path>, queue_capacity: usize) -> Result<Self> {
        let reader = PcapReader::open(path)?;
        let link_type = reader.header().link_type;
        let (ingress, consumer) = crate::queue::channel(queue_capacity);
        Ok(Self {
            reader: Some(reader),
            consumer,
            ingress,
            seen: 0,
            exhausted: false,
            link_type,
        })
    }

    /// The file's global header.
    #[must_use]
    pub const fn header_link_type(&self) -> u32 {
        self.link_type
    }

    /// Frames read so far.
    #[must_use]
    pub const fn packets_read(&self) -> u64 {
        self.seen
    }

    /// Number of frames still queued.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.consumer.stats().depth
    }

    /// The consumer half of the internal queue, for callers that drain it directly.
    #[must_use]
    pub const fn consumer(&self) -> &PacketConsumer {
        &self.consumer
    }

    /// Reads the remaining frames into the internal queue as fast as possible.
    ///
    /// This is the bulk path used by `sentinel analyze`: a file is finite, so reading it eagerly
    /// is simpler and faster than pacing it through a live-shaped loop. The queue capacity must
    /// therefore be at least as large as the file, or later frames are dropped and counted.
    ///
    /// # Errors
    /// Returns [`CaptureError::File`] on a truncated or unreadable record.
    pub fn load_remaining(&mut self) -> Result<OfflineSummary> {
        let mut summary = OfflineSummary {
            link_type: self.link_type,
            ..OfflineSummary::default()
        };
        let Some(reader) = self.reader.as_mut() else {
            self.exhausted = true;
            return Ok(summary);
        };

        loop {
            match reader.next_packet() {
                Ok(Some(packet)) => {
                    if summary.packets == 0 {
                        summary.first_seen_us = packet.timestamp_us;
                    }
                    summary.last_seen_us = packet.timestamp_us;
                    let raw = RawPacket::new(
                        packet.timestamp_us,
                        packet.captured_len,
                        packet.original_len,
                        Bytes::from(packet.data),
                    );
                    // A frame that overflowed the queue is counted as a frame read but not as a
                    // frame queued, so the summary never overstates what was captured.
                    summary.packets += self.ingress.push_counted(raw) as u64;
                    self.seen += 1;
                }
                Ok(None) => break,
                Err(err) => {
                    // A file cut mid-record is a normal forensic situation, not a crash: the
                    // frames read so far are still valid and are reported alongside the fact
                    // that the file was truncated.
                    summary.truncated = true;
                    tracing::warn!(error = %err, "capture file ended mid-record");
                    break;
                }
            }
        }

        self.exhausted = true;
        Ok(summary)
    }
}

impl CaptureProvider for OfflineCapture {
    fn backend_name(&self) -> &'static str {
        "pcap-file"
    }

    fn list_interfaces(&self) -> Result<Vec<sentinel_common::net::NetworkInterface>> {
        // A capture file has no interfaces. An empty list is accurate; inventing one would be a
        // lie the interface picker would then present to the user.
        Ok(Vec::new())
    }

    fn open(&mut self, _interface: &sentinel_common::net::NetworkInterface) -> Result<()> {
        // The file is opened in `OfflineCapture::open`; there is no device to acquire.
        Ok(())
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        if let Some(queued) = self.consumer.try_next() {
            return Ok(Some(queued));
        }
        if self.exhausted {
            return Ok(None);
        }

        let Some(reader) = self.reader.as_mut() else {
            self.exhausted = true;
            return Ok(None);
        };

        match reader.next_packet() {
            Ok(Some(packet)) => {
                self.seen += 1;
                Ok(Some(RawPacket::new(
                    packet.timestamp_us,
                    packet.captured_len,
                    packet.original_len,
                    Bytes::from(packet.data),
                )))
            }
            Ok(None) => {
                self.exhausted = true;
                Ok(None)
            }
            // A truncated final record ends iteration, having already yielded every complete
            // frame before it. The engine sees a clean end-of-stream.
            Err(err) => {
                tracing::warn!(error = %err, "capture file ended mid-record");
                self.exhausted = true;
                Ok(None)
            }
        }
    }

    fn close(&mut self) -> Result<()> {
        self.exhausted = true;
        self.reader = None;
        self.ingress.close();
        Ok(())
    }

    fn stats(&self) -> CaptureStats {
        // A file cannot lose frames, so there is no driver-level loss to report. A short queue
        // could still drop frames during bulk loading, so that count is included honestly.
        let queue = self.consumer.stats();
        CaptureStats {
            received: self.seen,
            dropped: queue.dropped,
            interface_dropped: 0,
        }
    }

    fn is_open(&self) -> bool {
        !self.exhausted
    }
}

#[cfg(test)]
mod tests {
    use sentinel_parser::fixtures;
    use sentinel_parser::pcap::{LINKTYPE_ETHERNET, PcapWriter};

    use super::*;

    fn write_capture(path: &Path, frames: &[(u64, Vec<u8>)]) {
        let mut writer =
            PcapWriter::create(path, LINKTYPE_ETHERNET, 65_535).expect("create capture");
        for (timestamp, frame) in frames {
            writer.write_packet(*timestamp, frame).expect("write frame");
        }
        writer.flush().expect("flush");
    }

    fn sample_frames() -> Vec<(u64, Vec<u8>)> {
        vec![
            (
                1_735_689_600_000_000,
                fixtures::tcp_frame(52_341, 443, 0x02, &[]),
            ),
            (
                1_735_689_600_100_000,
                fixtures::dns_query_frame(53_000, 0x1234, "example.com"),
            ),
            (1_735_689_600_250_000, fixtures::arp_request_frame()),
        ]
    }

    #[test]
    fn reads_a_capture_incrementally() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("capture.pcap");
        write_capture(&path, &sample_frames());

        let mut capture = OfflineCapture::open(&path, 64).expect("open capture");
        assert_eq!(capture.header_link_type(), LINKTYPE_ETHERNET);
        assert!(capture.is_open());

        let mut count = 0u64;
        while let Some(packet) = capture.next_packet().expect("read") {
            assert!(!packet.data.is_empty());
            count += 1;
        }
        assert_eq!(count, 3);
        assert!(!capture.is_open(), "exhaustion ends the session");
        assert!(capture.next_packet().expect("read past the end").is_none());
    }

    #[test]
    fn load_remaining_produces_a_summary() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("capture.pcap");
        write_capture(&path, &sample_frames());

        let mut capture = OfflineCapture::open(&path, 64).expect("open");
        let summary = capture.load_remaining().expect("load");

        assert_eq!(summary.packets, 3);
        assert_eq!(summary.first_seen_us, 1_735_689_600_000_000);
        assert_eq!(summary.last_seen_us, 1_735_689_600_250_000);
        assert_eq!(summary.duration_us(), 250_000);
        assert!(!summary.truncated);
        assert_eq!(capture.queue_len(), 3);
        assert_eq!(capture.packets_read(), 3);
    }

    #[test]
    fn an_empty_capture_yields_a_zero_summary() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("empty.pcap");

        let mut writer = PcapWriter::create(&path, LINKTYPE_ETHERNET, 1500).expect("create");
        writer.flush().expect("flush");

        let mut capture = OfflineCapture::open(&path, 16).expect("open");
        let summary = capture.load_remaining().expect("load");
        assert_eq!(summary.packets, 0);
        assert_eq!(summary.duration_us(), 0);
    }

    #[test]
    fn a_capture_file_has_no_interfaces() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("capture.pcap");
        write_capture(&path, &sample_frames());

        let capture = OfflineCapture::open(&path, 16).expect("open");
        assert!(capture.list_interfaces().expect("list").is_empty());
        assert_eq!(capture.backend_name(), "pcap-file");
    }

    #[test]
    fn a_pcapng_file_is_refused_with_guidance() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("capture.pcapng");
        std::fs::write(&path, 0x0a0d_0d0au32.to_le_bytes()).expect("write fixture");

        let Err(err) = OfflineCapture::open(&path, 16) else {
            panic!("pcapng must be refused")
        };
        let message = sentinel_common::error::UserFacing::user_message(&err).to_plain_text();
        assert!(
            message.contains("editcap"),
            "the message must name the converter"
        );
    }

    #[test]
    fn a_missing_file_is_reported() {
        let Err(err) = OfflineCapture::open("no-such-file.pcap", 16) else {
            panic!("missing file must fail")
        };
        assert!(matches!(err, crate::CaptureError::File(_)));
    }

    #[test]
    fn stats_report_every_frame_read() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("capture.pcap");
        write_capture(&path, &sample_frames());

        let mut capture = OfflineCapture::open(&path, 16).expect("open");
        capture.load_remaining().expect("load");

        let stats = capture.stats();
        assert_eq!(stats.received, 3);
        assert!(
            !stats.has_loss(),
            "a file with a roomy queue cannot lose frames"
        );
    }

    #[test]
    fn a_truncated_file_yields_its_complete_frames_and_says_so() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("truncated.pcap");
        write_capture(&path, &sample_frames());

        // Append a packet header promising more payload than exists.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("reopen");
        let mut lying = [0u8; 16];
        lying[8..12].copy_from_slice(&9999u32.to_le_bytes());
        lying[12..16].copy_from_slice(&9999u32.to_le_bytes());
        std::io::Write::write_all(&mut file, &lying).expect("append");

        let mut capture = OfflineCapture::open(&path, 64).expect("open");
        let summary = capture.load_remaining().expect("load");

        assert_eq!(
            summary.packets, 3,
            "every complete frame before the truncation is kept"
        );
        assert!(
            summary.truncated,
            "the report must say the file was cut short"
        );
    }

    #[test]
    fn closing_is_idempotent() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("capture.pcap");
        write_capture(&path, &sample_frames());

        let mut capture = OfflineCapture::open(&path, 16).expect("open");
        assert!(capture.close().is_ok());
        assert!(capture.close().is_ok());
        assert!(!capture.is_open());
    }
}
