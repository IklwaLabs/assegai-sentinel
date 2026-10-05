//! Generates a small, deterministic PCAP fixture for demos, manual testing and CLI
//! verification.
//!
//! Golden fixtures are generated rather than committed as binaries so the contents are
//! reviewable, byte for byte, in the source. Run with:
//!
//! ```text
//! cargo run -p sentinel-fixtures -- fixtures/demo-traffic.pcap
//! ```
//!
//! The traffic is a plausible small home-network session: a TLS handshake and bulk transfer to
//! a web host, two DNS queries with a response, an ICMP echo, ARP resolution for the gateway,
//! a non-initial IPv4 fragment, one malformed frame, and a connection to an unexpected port.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use sentinel_parser::fixtures;
use sentinel_parser::pcap::{LINKTYPE_ETHERNET, PcapWriter};

/// Start of the capture: 2025-01-01T00:00:00Z.
const START_US: u64 = 1_735_689_600_000_000;

fn main() -> anyhow::Result<()> {
    let destination = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures/demo-traffic.pcap"));

    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let frames = build_traffic();
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_demo_capture_writes_and_reads_back() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("demo.pcap");

        let frames = build_traffic();
        {
            let mut writer = PcapWriter::create(&path, LINKTYPE_ETHERNET, 65_535).expect("create");
            for (timestamp, frame) in &frames {
                writer
                    .write_packet(START_US + timestamp, frame)
                    .expect("write");
            }
            writer.flush().expect("flush");
        }

        let mut reader = sentinel_parser::PcapReader::open(&path).expect("open");
        let mut count = 0;
        while reader.next_packet().expect("read").is_some() {
            count += 1;
        }
        assert_eq!(count, frames.len());
    }
}
