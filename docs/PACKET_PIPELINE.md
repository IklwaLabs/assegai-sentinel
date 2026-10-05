# The Packet Pipeline

How a frame becomes a row in the connections table, and what happens to it at every step. This
document exists because most of Sentinel's behaviour is decided here, and a surprising number of
numbers on screen are only correct if these steps are right.

## The path

```text
  wire
   |
   v
[1] capture thread        libpcap blocks; copies bytes into a bounded queue
   |
   v  (bounded queue, drop-counted)
[2] engine drain          every 25ms, drain all available, bounded per tick
   |
   v
[3] decode                Ethernet -> VLAN -> IPv4/IPv6 -> TCP/UDP/ICMP -> NormalizedPacket
   |                        failures are counted, never fatal
   v
[4] flow key              canonical endpoint pair + protocol
   |
   v
[5] flow table            lookup or create; update counters; mark direction
   |
   v
[6] aggregation           1-second buckets, upload/download split
   |
   +------> [7] snapshot  every 250ms, throttled, to the UI
   |
   v
[8] storage               every 5s, batched, in the writer thread
```

Steps 1 and 2 are separate because they have different failure modes. Capture blocking on a
socket and analysis sharing a thread would mean a slow disk stalls the reader and the kernel
starts dropping. Instead the reader only ever copies bytes, and the consequence of falling behind
is a *count* — which the interface shows, because a total derived from lossy data presented as
complete is a lie.

## 1. Capture

`sentinel-capture` runs the blocking read loop on a dedicated OS thread. It owns the libpcap
handle, applies the BPF filter at the driver so unselected traffic never crosses into user
space, and pushes each frame into a bounded `sync_channel`.

Two halves, not one channel, because `std::sync::mpsc::Receiver` is `Send` but not `Sync`. The
producer half (`PacketIngress`) is `Sync` and goes to the capture thread; the consumer half
(`PacketConsumer`) is `Send` and stays with the engine. The same shape applies to the storage
writer's shutdown path.

When the queue is full the frame is dropped and a counter increments. This is the design
decision most worth defending: dropping and counting is honest, unbounded buffering is a lie
that ends in an out-of-memory kill, and blocking the reader would push the loss into the driver
where it is harder to attribute.

## 2. Drain

The engine wakes every 25 ms and drains everything available, in chunks of 4 096 frames, up to
250 000 per tick. The chunking is not about throughput: it exists so the borrow of the capture
adapter can end before the pipeline needs `&mut self`, and so a burst cannot buffer an unbounded
number of frames in memory.

The per-tick cap keeps one very busy interface from starving request handling. A start or stop
command arriving during a burst should not wait for the burst to finish.

## 3. Decode

`crates/sentinel-parser` implements its own L2–L4 decoder rather than delegating to
`etherparse`. That decision is deliberate and worth stating: `etherparse` 0.14's nested-slice
API does not expose ARP, and hides truncation and IP fragmentation behind conveniences that lose
exactly the information the flow engine needs. Owning ~400 lines of bounds-checked decoding buys
explicit handling of every case below.

Every read is bounds-checked. A frame that is too short produces a counted error, never a panic
and never a partial parse that silently misattributes traffic.

Specific cases that matter:

| Case | Handling | Why |
| --- | --- | --- |
| VLAN tags | Unwrapped, up to a bounded depth of stacked tags | A trunk capture must decode the inner protocol, not stop at 802.1Q. |
| Non-initial IPv4 fragment | Decoded, then **excluded from flow accounting** | It has an IP header but no ports. Keying it would create a second portless flow for a connection that already has one, splitting its byte counts. |
| Truncated by snaplen | Decoded from what is present, `truncated` set | A small snaplen must not look like a malformed frame. |
| ARP | Decoded, no flow | It is real traffic with no flow identity. |
| ICMP | A portless flow | Correct: it is tracked, with `port: None`, rather than dropped. |
| Malformed | Counted as a decode error | One bad frame must not end the session. |

## 4. Flow key

A flow is identified by a protocol plus a **canonically ordered** endpoint pair. Ordering by
`(address, port)` makes the key independent of which side sent first, so a reply finds the
existing flow without needing a direction.

The trade-off: the key no longer records direction. Direction is therefore a separate fact,
inferred from port roles — the side using an ephemeral port opened the connection. The
interface reports the two separately, because they are different claims:

- `source` / `destination` — oriented by initiator, with `initiatorKnown` saying whether that
  inference had any basis
- `local` / `remote` — filled only when an endpoint matches one of this machine's addresses

Showing `endpoint_b` in a column labelled "remote" would display the user's own address as the
remote. That is why orientation is explicit rather than implied by column order.

## 5. Flow table

A hash map from key to flow, with:

- **an idle timeout** (default 120 s), swept periodically rather than on every packet
- **a capacity cap** (default 65 536), evicting the oldest by last-seen
- **sweep cadence scaled to throughput**, so a fast network sweeps less often in packet terms

Both bounds exist for the same reason: a long-running capture must not grow without limit. The
idle timeout handles connections that simply end; the cap handles the case where the timeout
alone is not enough.

Sweeping is cheap enough to run on a cadence — one pass over the table every few hundred
packets — which is why it does not need a timer thread.

## 6. Aggregation

Traffic is bucketed into one-second windows keyed by timestamp. Out-of-order frames merge into
their correct bucket rather than creating a new one, because capture timestamps are not
monotonic and a reordering would otherwise show as a spike followed by a gap.

Upload and download are split by the flow's direction, so the chart shows what was sent and what
was received rather than a single undifferentiated total.

Bucket timestamps are whole seconds. Anything needing finer resolution — a true capture span —
is taken from the first and last frame timestamps directly, not inferred from bucket boundaries.

## 7. Snapshots

Every 250 ms the engine publishes one `EngineSnapshot`: state, totals, the traffic series, the
most recent connections, pipeline counters, queue accounting and the effective configuration.

Two properties matter:

- **The snapshot is complete.** A view can render everything from it, so no frontend ever needs
  a second request mid-frame.
- **It is bounded.** Connection count is capped (default 200) and the traffic series is a ring.
  Serialising cost therefore does not grow with capture duration, which is what keeps a
  long-running session responsive.

## 8. Storage

Flows and traffic samples are written every 5 seconds into a batched writer thread that owns the
SQLite connection. The engine submits work and moves on; it never blocks on the disk.

Two subtleties:

- **Protocol totals are cumulative for a session but written as deltas.** Sending the session
  total on every flush would double-count on every flush.
- **Retention runs inside the writer's transaction**, not on a second connection. SQLite has one
  writer; a second connection would contend for the lock and the loser would report a spurious
  "database is locked" to the user.

Flows are written once they close or go quiet for 10 seconds. Active flows stay in memory for the
live view and are written later, so killing the app does not lose a long-lived connection.

## Where loss can happen, and how it is reported

| Loss | Counter | Surfaced as |
| --- | --- | --- |
| Driver could not keep up | `CaptureStats::dropped` | "Frames lost" in the CLI, a notice in the UI |
| Driver reported interface drops | `CaptureStats::interface_dropped` | Same |
| Engine queue full | `PacketIngress` drop counter | `stats.queue.dropped` |
| Truncated by snaplen | `truncated_packets` | Decoder counters |
| Undecodable frame | `decode_errors` | Decoder counters |

Every one of these is counted, and every surface that shows totals tells you when they are
non-zero. That is the difference between a monitoring tool and a plausible-looking one.

## Testing this pipeline

`crates/sentinel-core/tests/offline_pipeline.rs` runs generated frames through the real
`OfflineCapture` → `Pipeline` chain and asserts on the resulting flows: bidirectional
aggregation, initiator detection, ARP exclusion, ICMP portlessness, IPv6 keying, VLAN decoding,
fragment exclusion, malformed-frame resilience, byte accounting, and bucket ordering.

No capture driver, no privileges and no network are required, because the pipeline is exercised
through the same code path either way. That is the property being tested: live capture and file
analysis are not two implementations, they are one.