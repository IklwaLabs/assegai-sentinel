//! End-to-end tests for the offline analysis path.
//!
//! These are the tests that prove the core promise of the architecture: a PCAP file and a live
//! capture are analysed by **the same** code. Each test writes a capture file with the
//! dependency-free writer, runs it through the real `OfflineCapture` -> `Pipeline` chain, and
//! asserts on the resulting flows. No capture driver, no elevated privileges, no live network.

use sentinel_capture::{CaptureProvider, OfflineCapture};
use sentinel_common::config::AppConfig;
use sentinel_core::event::ConnectionRow;
use sentinel_core::pipeline::{Pipeline, PipelineConfig};
use sentinel_flow::key::FlowKey;
use sentinel_parser::fixtures;
use sentinel_parser::pcap::{LINKTYPE_ETHERNET, PcapWriter};

/// Builds a pipeline configured like the default desktop session.
fn pipeline() -> Pipeline {
    let config = AppConfig::default();
    let mut pipeline = Pipeline::new(PipelineConfig::from_capture_config(&config.capture));
    pipeline.set_local_addresses(vec!["192.168.1.10".parse().expect("valid local address")]);
    pipeline
}

/// Writes a capture file and returns its path.
fn write_capture(frames: &[(u64, Vec<u8>)]) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::with_suffix(".pcap").expect("temp capture");
    let mut writer =
        PcapWriter::create(file.path(), LINKTYPE_ETHERNET, 65_535).expect("create capture");
    for (timestamp, frame) in frames {
        writer.write_packet(*timestamp, frame).expect("write frame");
    }
    writer.flush().expect("flush");
    file
}

/// Runs a capture file through the pipeline, returning the pipeline and its counters.
fn analyze(frames: &[(u64, Vec<u8>)]) -> (Pipeline, sentinel_core::pipeline::PipelineCounters) {
    let file = write_capture(frames);
    let mut capture = OfflineCapture::open(file.path(), 1_024).expect("open capture");
    let mut pipeline = pipeline();

    while let Some(raw) = capture.next_packet().expect("read frame") {
        let _ = pipeline.process(&raw, None);
    }
    let counters = pipeline.counters();
    (pipeline, counters)
}

/// A single TCP connection becomes exactly one bidirectional flow.
#[test]
fn a_tcp_exchange_becomes_one_flow_with_both_directions() {
    let frames = vec![
        // SYN from the client on an ephemeral port to a service on 443.
        (1_000_000, fixtures::tcp_frame(52_341, 443, 0x02, &[])),
        // SYN-ACK reply.
        (1_000_100, fixtures::tcp_reply_frame(443, 52_341, 0x12, &[])),
        // Payload in both directions.
        (
            1_000_200,
            fixtures::tcp_frame(52_341, 443, 0x18, &[0u8; 100]),
        ),
        (
            1_000_300,
            fixtures::tcp_reply_frame(443, 52_341, 0x18, &[0u8; 400]),
        ),
    ];

    let (pipeline, counters) = analyze(&frames);

    assert_eq!(
        pipeline.flow_count(),
        1,
        "a reply must land in the same flow"
    );
    assert_eq!(counters.packets_decoded, 4);
    assert_eq!(counters.flows_created, 1);
    assert_eq!(counters.decode_errors, 0);
    assert_eq!(counters.packets_without_flow, 0);

    let flow = pipeline.flows_by_recent(10).remove(0);
    assert_eq!(flow.total_packets(), 4);
    assert_eq!(
        flow.service.as_deref(),
        Some("HTTPS"),
        "the service is inferred from port 443"
    );
    assert!(
        flow.bytes_received > flow.bytes_sent,
        "the larger direction must be attributed to the responder, not the initiator"
    );
}

/// Reply traffic never splits a flow, even across many packets.
#[test]
fn bidirectional_traffic_aggregates_into_one_flow() {
    let mut frames = Vec::new();
    for index in 0..50u64 {
        frames.push((
            1_000_000 + index * 1_000,
            fixtures::tcp_frame(52_341, 443, 0x18, &[0u8; 10]),
        ));
        frames.push((
            1_000_500 + index * 1_000,
            fixtures::tcp_reply_frame(443, 52_341, 0x18, &[0u8; 10]),
        ));
    }

    let (pipeline, counters) = analyze(&frames);
    assert_eq!(pipeline.flow_count(), 1);
    assert_eq!(counters.packets_decoded, 100);
    assert_eq!(counters.flows_created, 1);
    assert_eq!(pipeline.flows_by_recent(1)[0].total_packets(), 100);
}

/// Distinct remote hosts produce distinct flows.
#[test]
fn separate_destinations_produce_separate_flows() {
    let frames = vec![
        (1_000_000, fixtures::tcp_frame(52_341, 443, 0x02, &[])),
        (2_000_000, {
            let mut frame = fixtures::tcp_frame(52_342, 443, 0x02, &[]);
            // Rewrite the destination address to a different host.
            let dst = frame.len() - 20 - 20;
            frame[dst + 14..dst + 18].copy_from_slice(&[1, 1, 1, 1]);
            frame
        }),
    ];

    let (pipeline, _) = analyze(&frames);
    assert_eq!(pipeline.flow_count(), 2);
}

/// UDP DNS traffic is tracked with the DNS service attached.
#[test]
fn dns_queries_are_tracked_and_identified() {
    let frames = vec![
        (
            1_000_000,
            fixtures::dns_query_frame(53_000, 0x1234, "example.com"),
        ),
        (
            1_000_500,
            fixtures::dns_query_frame(53_001, 0x1235, "example.org"),
        ),
    ];

    let (pipeline, _) = analyze(&frames);
    assert_eq!(
        pipeline.flow_count(),
        2,
        "each source port is a separate query flow"
    );

    let flows = pipeline.flows_by_recent(10);
    assert!(
        flows
            .iter()
            .all(|flow| flow.service.as_deref() == Some("DNS"))
    );
    assert!(
        flows
            .iter()
            .all(|flow| flow.key.protocol == sentinel_common::packet::TransportProtocol::Udp)
    );
}

/// ARP traffic is decoded but never becomes a flow.
#[test]
fn arp_is_decoded_without_becoming_a_flow() {
    let frames = vec![
        (1_000_000, fixtures::arp_request_frame()),
        (1_000_100, fixtures::arp_reply_frame()),
    ];

    let (pipeline, counters) = analyze(&frames);

    assert_eq!(counters.packets_decoded, 2, "ARP is decoded, not skipped");
    assert_eq!(
        counters.packets_without_flow, 2,
        "but it has no flow identity"
    );
    assert_eq!(pipeline.flow_count(), 0);
    assert_eq!(counters.decode_errors, 0);
}

/// ICMP is tracked as a portless flow.
#[test]
fn icmp_is_tracked_as_a_portless_flow() {
    let frames = vec![
        (1_000_000, fixtures::icmp_echo_frame()),
        (1_000_100, fixtures::icmp_echo_frame()),
    ];

    let (pipeline, counters) = analyze(&frames);
    assert_eq!(counters.packets_without_flow, 0);
    assert_eq!(pipeline.flow_count(), 1);

    let flow = &pipeline.flows_by_recent(1)[0];
    assert_eq!(
        flow.key.protocol,
        sentinel_common::packet::TransportProtocol::Icmp
    );
    assert_eq!(
        flow.key.endpoint_a.port, None,
        "ICMP has no ports to attribute"
    );
}

/// IPv6 traffic is decoded and keyed like IPv4.
#[test]
fn ipv6_traffic_is_keyed_correctly() {
    let frames = vec![
        (1_000_000, fixtures::ipv6_tcp_frame(49_152, 443, 0x02)),
        (1_000_100, fixtures::ipv6_tcp_reply_frame(443, 49_152, 0x12)),
    ];

    let (pipeline, counters) = analyze(&frames);
    assert_eq!(counters.packets_decoded, 2);
    assert_eq!(
        pipeline.flow_count(),
        1,
        "an IPv6 reply shares the flow with its request"
    );
}

/// VLAN tags do not prevent the inner protocol from being decoded.
#[test]
fn vlan_tagged_traffic_is_decoded() {
    let frames = vec![(1_000_000, fixtures::vlan_udp_frame(100, 3, 1_234, 53))];

    let (pipeline, counters) = analyze(&frames);
    assert_eq!(counters.packets_decoded, 1);
    assert_eq!(pipeline.flow_count(), 1);

    let flow = &pipeline.flows_by_recent(1)[0];
    assert_eq!(
        flow.key.endpoint_a.port.or(flow.key.endpoint_b.port),
        Some(53)
    );
    assert_eq!(flow.service.as_deref(), Some("DNS"));
}

/// Malformed frames are counted and skipped, never fatal.
#[test]
fn malformed_frames_are_counted_without_ending_the_analysis() {
    // A frame whose Ethernet header is truncated to four bytes, followed by good traffic.
    let truncated = vec![0xff, 0xff, 0xff, 0xff];
    let frames = vec![
        (1_000_000, truncated),
        (1_000_100, fixtures::tcp_frame(52_341, 443, 0x02, &[])),
        (1_000_200, vec![0u8; 3]),
        (1_000_300, fixtures::tcp_frame(52_341, 443, 0x12, &[])),
    ];

    let (pipeline, counters) = analyze(&frames);

    assert_eq!(
        counters.decode_errors, 2,
        "both malformed frames are counted"
    );
    assert_eq!(
        counters.packets_decoded, 2,
        "the good frames are still analysed"
    );
    assert_eq!(
        pipeline.flow_count(),
        1,
        "analysis continued past the bad frames"
    );
}

/// A non-initial fragment does not invent a flow.
#[test]
fn non_initial_fragments_do_not_create_phantom_flows() {
    let frames = vec![
        (1_000_000, fixtures::tcp_frame(52_341, 443, 0x02, &[])),
        (1_000_100, fixtures::ipv4_non_initial_fragment(185)),
        (1_000_200, fixtures::tcp_reply_frame(443, 52_341, 0x12, &[])),
    ];

    let (pipeline, counters) = analyze(&frames);

    assert_eq!(
        pipeline.flow_count(),
        1,
        "the fragment must not create a second flow"
    );
    assert_eq!(
        counters.packets_without_flow, 1,
        "the fragment has no transport header"
    );
    assert_eq!(counters.packets_decoded, 3);
}

/// Traffic accounting matches the bytes on the wire.
#[test]
fn traffic_totals_match_the_capture() {
    let frame = fixtures::tcp_frame(52_341, 443, 0x18, &[0u8; 100]);
    let wire_len = frame.len() as u64;
    let frames = vec![
        (1_000_000, frame),
        (
            2_000_000,
            fixtures::tcp_reply_frame(443, 52_341, 0x18, &[0u8; 100]),
        ),
    ];

    let (pipeline, _) = analyze(&frames);
    let summary = pipeline.traffic_summary();

    assert_eq!(summary.packets, 2);
    assert_eq!(
        summary.total_bytes(),
        wire_len * 2,
        "byte totals come from the wire length"
    );
    assert_eq!(
        summary.upload_bytes + summary.download_bytes,
        summary.total_bytes()
    );
    assert!(
        summary.upload_bytes > 0 && summary.download_bytes > 0,
        "both directions are counted"
    );
}

/// The chart series is bucketed by timestamp, not by arrival order.
#[test]
fn traffic_samples_are_bucketed_by_time() {
    let frames = vec![
        (
            1_000_000,
            fixtures::tcp_frame(52_341, 443, 0x18, &[0u8; 10]),
        ),
        (
            1_500_000,
            fixtures::tcp_reply_frame(443, 52_341, 0x18, &[0u8; 10]),
        ),
        (
            3_000_000,
            fixtures::tcp_frame(52_341, 443, 0x18, &[0u8; 10]),
        ),
    ];

    let (pipeline, _) = analyze(&frames);
    let samples = pipeline.traffic_samples();

    assert!(
        samples.len() >= 3,
        "two seconds of traffic plus the gap: {}",
        samples.len()
    );
    assert_eq!(samples[0].bucket_start_us, 1_000_000);
    assert_eq!(samples.last().expect("a sample").bucket_start_us, 3_000_000);
    assert!(
        samples
            .windows(2)
            .all(|pair| pair[0].bucket_start_us < pair[1].bucket_start_us)
    );
}

/// An empty capture produces an empty, non-panicking result.
#[test]
fn an_empty_capture_analyses_to_nothing() {
    let (pipeline, counters) = analyze(&[]);
    assert_eq!(pipeline.flow_count(), 0);
    assert_eq!(counters.packets_seen, 0);
    assert_eq!(pipeline.traffic_summary().packets, 0);
    assert!(pipeline.traffic_samples().is_empty());
}

/// The flow key used by the API is the same key the pipeline tracks.
#[test]
fn connection_rows_carry_a_stable_identifier() {
    let frames = vec![(1_000_000, fixtures::tcp_frame(52_341, 443, 0x02, &[]))];
    let (pipeline, _) = analyze(&frames);

    let flow = &pipeline.flows_by_recent(1)[0];
    let row = ConnectionRow::from_flow(flow);

    // The row's endpoints come from the same normalized key, so the id is stable across runs
    // and across a restart that re-reads the same capture.
    let expected = FlowKey::from_packet(
        &sentinel_parser::PacketDecoder::new()
            .decode(
                &frames[0].1,
                1_000_000,
                frames[0].1.len() as u32,
                frames[0].1.len() as u32,
            )
            .expect("decode"),
    )
    .expect("flow key");
    assert_eq!(flow.key, expected);
    assert!(row.id.contains("tcp"));
    assert_eq!(row.protocol, "TCP");
}

/// Idle flows are swept out of the working set without being lost from the counters.
#[test]
fn the_flow_table_evicts_idle_flows() {
    let config = AppConfig::default();
    let mut pipeline_config = PipelineConfig::from_capture_config(&config.capture);
    // A short idle timeout makes the sweep observable without waiting.
    pipeline_config.flow_table.idle_timeout_us = 1_000_000;

    let mut pipeline = Pipeline::new(pipeline_config);
    let frame = fixtures::tcp_frame(52_341, 443, 0x02, &[]);
    let raw = sentinel_capture::RawPacket::new(
        1_000_000,
        frame.len() as u32,
        frame.len() as u32,
        bytes::Bytes::from(frame),
    );
    let _ = pipeline.process(&raw, None);
    assert_eq!(pipeline.flow_count(), 1);

    let result = pipeline.sweep(5_000_000, None);
    assert_eq!(result.expired, 1);
    assert_eq!(pipeline.flow_count(), 0);
    assert_eq!(
        pipeline.counters().flows_created,
        1,
        "the creation is still accounted for"
    );
}

/// Resetting the pipeline clears state but keeps the configuration.
#[test]
fn reset_clears_state_and_counters() {
    let frames = vec![(1_000_000, fixtures::tcp_frame(52_341, 443, 0x02, &[]))];
    let (mut pipeline, _) = analyze(&frames);
    assert_eq!(pipeline.flow_count(), 1);

    pipeline.reset();

    assert_eq!(pipeline.flow_count(), 0);
    assert_eq!(pipeline.counters().packets_seen, 0);
    assert!(pipeline.traffic_samples().is_empty());
}
