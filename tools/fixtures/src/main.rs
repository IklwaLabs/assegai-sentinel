//! Generates small, deterministic PCAP fixtures for demos, manual testing and CLI
//! verification.
//!
//! Golden fixtures are generated rather than committed as binaries so the contents are
//! reviewable, byte for byte, in the source. Run with:
//!
//! ```text
//! cargo run -p sentinel-fixtures -- fixtures/demo-traffic.pcap
//! cargo run -p sentinel-fixtures -- fixtures/detection-traffic.pcap --detections
//! ```
//!
//! `demo-traffic.pcap` is a plausible small home-network session: a TLS handshake and bulk
//! transfer to a web host, two DNS queries with a response, an ICMP echo, ARP resolution for the
//! gateway, a non-initial IPv4 fragment, one malformed frame, and a connection to an unexpected
//! port. Nothing in it crosses a detection threshold, which makes it the negative case.
//!
//! `detection-traffic.pcap` is deliberately hostile: an ARP address takeover, a port scan, a
//! host sweep, a cleartext login attempt and a null-flag probe. It exists so that "does the
//! engine detect anything" can be answered without a live network or a privileged capture.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use sentinel_parser::fixtures;
use sentinel_parser::pcap::{LINKTYPE_ETHERNET, PcapWriter};

/// Start of the capture: 2025-01-01T00:00:00Z.
const START_US: u64 = 1_735_689_600_000_000;

/// Which capture to generate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// Ordinary traffic that must not produce findings.
    Demo,
    /// Traffic that exercises every implemented detector.
    Detections,
}

impl Scenario {
    /// The path used when the caller does not name one.
    fn default_path(self) -> PathBuf {
        match self {
            Self::Demo => PathBuf::from("fixtures/demo-traffic.pcap"),
            Self::Detections => PathBuf::from("fixtures/detection-traffic.pcap"),
        }
    }

    /// The frames for this scenario.
    fn frames(self) -> Vec<(u64, Vec<u8>)> {
        match self {
            Self::Demo => build_traffic(),
            Self::Detections => build_detection_traffic(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut scenario = Scenario::Demo;
    let mut destination: Option<PathBuf> = None;

    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--detections" => scenario = Scenario::Detections,
            _ => destination = Some(PathBuf::from(argument)),
        }
    }

    let destination = destination.unwrap_or_else(|| scenario.default_path());

    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let frames = scenario.frames();
    let mut writer = PcapWriter::create(&destination, LINKTYPE_ETHERNET, 65_535)?;

    for (offset_us, frame) in &frames {
        writer.write_packet(START_US + offset_us, frame)?;
    }
    writer.flush()?;

    println!("Wrote {} frames to {}", frames.len(), destination.display());
    Ok(())
}

/// Builds the demo capture: `(timestamp offset in microseconds, frame)`.
fn build_traffic() -> Vec<(u64, Vec<u8>)> {
    let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut at = 0u64;

    // A gapless helper: every frame advances the clock by a plausible interval.
    let mut push = |frames: &mut Vec<(u64, Vec<u8>)>, gap_us: u64, frame: Vec<u8>| {
        frames.push((at, frame));
        at += gap_us;
    };

    // 1. ARP request for the default gateway, then its reply.
    push(&mut frames, 0, fixtures::arp_request_frame());
    push(&mut frames, 2_000, fixtures::arp_reply_frame());

    // 2. DNS query and response for the web host.
    push(
        &mut frames,
        5_000,
        fixtures::dns_query_frame(53_012, 0x1a2b, "example.com"),
    );
    push(
        &mut frames,
        20_000,
        fixtures::dns_response_frame(
            53_012,
            0x1a2b,
            "example.com",
            Ipv4Addr::new(93, 184, 216, 34),
        ),
    );

    // 3. A DNS query that never gets an answer, which is the shape a failed lookup takes.
    push(
        &mut frames,
        10_000,
        fixtures::dns_query_frame(53_013, 0x1a2c, "telemetry.invalid"),
    );

    // 4. ICMP echo to a public resolver, and its reply.
    push(&mut frames, 15_000, fixtures::icmp_echo_frame());

    // 5. A full TLS-shaped TCP exchange: SYN, SYN-ACK, ACK, data both ways, FIN.
    let client_port = 52_341u16;
    push(
        &mut frames,
        1_000,
        fixtures::tcp_frame(client_port, 443, 0x02, &[]),
    );
    push(
        &mut frames,
        12_000,
        fixtures::tcp_reply_frame(443, client_port, 0x12, &[]),
    );
    push(
        &mut frames,
        1_000,
        fixtures::tcp_frame(client_port, 443, 0x10, &[]),
    );
    push(
        &mut frames,
        2_000,
        fixtures::tcp_frame(client_port, 443, 0x18, &[0u8; 1_400]),
    );
    push(
        &mut frames,
        40_000,
        fixtures::tcp_reply_frame(443, client_port, 0x18, &[0u8; 28_000]),
    );
    push(
        &mut frames,
        30_000,
        fixtures::tcp_frame(client_port, 443, 0x18, &[0u8; 6_000]),
    );
    push(
        &mut frames,
        25_000,
        fixtures::tcp_reply_frame(443, client_port, 0x11, &[]),
    );

    // 6. A second connection on an unexpected port, which is what a scan or an odd service
    //    looks like in a capture.
    push(
        &mut frames,
        3_000,
        fixtures::tcp_frame(52_400, 4444, 0x02, &[]),
    );
    push(
        &mut frames,
        8_000,
        fixtures::tcp_frame(52_401, 8081, 0x02, &[]),
    );

    // 7. A non-initial fragment, which must not be mistaken for its own connection.
    push(&mut frames, 1_500, fixtures::ipv4_non_initial_fragment(185));

    // 8. A VLAN-tagged frame, so a capture taken on a trunk port is realistic.
    push(
        &mut frames,
        2_000,
        fixtures::vlan_udp_frame(100, 3, 53_020, 53),
    );

    // 9. A malformed frame, because real captures contain them and Sentinel must survive them.
    push(&mut frames, 500, vec![0xff, 0xff, 0xff]);

    frames
}

/// Builds a capture that crosses every implemented detection threshold.
///
/// The frames are ordinary on the wire — there is nothing here that a parser has to special-case
/// — but the behaviour is hostile: one address taken over, one host probing many ports, one host
/// probing many machines, a login protocol in the clear, and a TCP header no ordinary stack emits.
///
/// Thresholds are 20 ports, 20 hosts and 8 beacon intervals, so the counts below are given a
/// small margin rather than sitting exactly on the boundary. A fixture that only just fires
/// stops firing the first time a threshold is tuned, and then nobody notices.
fn build_detection_traffic() -> Vec<(u64, Vec<u8>)> {
    let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut at = 0u64;

    let mut push = |frames: &mut Vec<(u64, Vec<u8>)>, gap_us: u64, frame: Vec<u8>| {
        frames.push((at, frame));
        at += gap_us;
    };

    const GATEWAY_IP: [u8; 4] = [192, 168, 1, 1];
    const REAL_GATEWAY_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc];
    const IMPOSTOR_MAC: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    // 1. ARP address takeover. The gateway answers as itself, then the impostor claims the same
    //    address, then the real gateway answers again. That last reply is what separates an
    //    attack from a DHCP hand-off: two devices are demonstrably answering at once.
    push(
        &mut frames,
        0,
        fixtures::arp_reply_frame_with_identity(GATEWAY_IP, REAL_GATEWAY_MAC),
    );
    push(
        &mut frames,
        1_000_000,
        fixtures::arp_reply_frame_with_identity(GATEWAY_IP, IMPOSTOR_MAC),
    );
    push(
        &mut frames,
        1_000_000,
        fixtures::arp_reply_frame_with_identity(GATEWAY_IP, REAL_GATEWAY_MAC),
    );

    // 2. A vertical port scan: twenty-four ports on one host, well inside the 60-second window.
    //    The ports are high on purpose; low ones would also fire the cleartext rule and make it
    //    unclear which detector produced the finding.
    for offset in 0..24u16 {
        push(
            &mut frames,
            2_000,
            fixtures::tcp_frame_between(
                fixtures::SRC_IP,
                fixtures::DST_IP,
                40_000 + offset,
                5_000 + offset,
                0x02,
                &[],
            ),
        );
    }

    // 3. A horizontal host sweep: the same port across twenty-four machines. A fast scanner does
    //    this at the same time as the vertical scan, which is why the two rules are independent.
    for offset in 0..24u8 {
        push(
            &mut frames,
            2_000,
            fixtures::tcp_frame_between(
                fixtures::SRC_IP,
                [192, 168, 1, 20 + offset],
                41_000 + u16::from(offset),
                445,
                0x02,
                &[],
            ),
        );
    }

    // 4. A Telnet connection attempt. The port is the only evidence available, because payload
    //    bytes are never retained or inspected.
    push(
        &mut frames,
        5_000,
        fixtures::tcp_frame_between(fixtures::SRC_IP, [192, 168, 1, 30], 42_000, 23, 0x02, &[]),
    );

    // 5. A null-flag probe: no SYN, no ACK, no FIN. No ordinary TCP stack emits this, which is
    //    what makes it reportable from the header alone.
    push(
        &mut frames,
        5_000,
        fixtures::tcp_frame_between(fixtures::SRC_IP, fixtures::DST_IP, 42_100, 8_080, 0x00, &[]),
    );

    frames
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use sentinel_capture::{CaptureProvider, OfflineCapture};
    use sentinel_common::config::AppConfig;
    use sentinel_core::pipeline::{Pipeline, PipelineConfig};

    /// Writes a scenario to `path` and returns the frame count.
    fn write_scenario(path: &std::path::Path, scenario: Scenario) -> usize {
        let frames = scenario.frames();
        let mut writer =
            PcapWriter::create(path, LINKTYPE_ETHERNET, 65_535).expect("create capture");
        for (timestamp, frame) in &frames {
            writer
                .write_packet(START_US + timestamp, frame)
                .expect("write");
        }
        writer.flush().expect("flush");
        frames.len()
    }

    #[test]
    fn the_demo_capture_is_ordered_and_non_empty() {
        let frames = build_traffic();
        assert!(
            frames.len() >= 15,
            "the demo should exercise every decoder path"
        );
        assert!(
            frames.windows(2).all(|pair| pair[0].0 <= pair[1].0),
            "timestamps must be ordered"
        );
    }

    #[test]
    fn the_detection_capture_is_ordered_and_non_empty() {
        let frames = build_detection_traffic();
        assert!(
            frames.windows(2).all(|pair| pair[0].0 <= pair[1].0),
            "timestamps must be ordered"
        );
    }

    #[test]
    fn the_demo_capture_writes_and_reads_back() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("demo.pcap");
        let expected = write_scenario(&path, Scenario::Demo);

        let mut reader = sentinel_parser::PcapReader::open(&path).expect("open");
        let mut count = 0;
        while reader.next_packet().expect("read").is_some() {
            count += 1;
        }
        assert_eq!(count, expected);
    }

    #[test]
    fn the_detection_capture_writes_and_reads_back() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("detections.pcap");
        let expected = write_scenario(&path, Scenario::Detections);

        let mut reader = sentinel_parser::PcapReader::open(&path).expect("open");
        let mut count = 0;
        while reader.next_packet().expect("read").is_some() {
            count += 1;
        }
        assert_eq!(count, expected);
    }

    /// The point of the detection fixture is that the engine fires on it. If a threshold is
    /// retuned and this fixture stops producing its findings, the demo becomes a lie, so the
    /// claim is pinned here rather than in a document.
    #[test]
    fn the_detection_capture_produces_every_expected_finding() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("detections.pcap");
        write_scenario(&path, Scenario::Detections);

        let config = AppConfig::default();
        let mut pipeline = Pipeline::new(PipelineConfig::from_capture_config(&config.capture));
        let mut capture = OfflineCapture::open(&path, 1_024).expect("open capture");
        while let Some(raw) = capture.next_packet().expect("read frame") {
            let _ = pipeline.process(&raw, None);
        }

        let kinds: BTreeSet<&str> = pipeline
            .findings()
            .iter()
            .map(|finding| finding.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            BTreeSet::from([
                "arpSpoofing",
                "cleartextProtocol",
                "hostSweep",
                "portScan",
                "tcpFlagAnomaly",
            ]),
            "the fixture must exercise every detector exactly as documented"
        );
        assert_eq!(
            pipeline.finding_count(),
            5,
            "one finding per behaviour, not one per packet"
        );
        assert_eq!(pipeline.findings_suppressed(), 0);
    }
}
