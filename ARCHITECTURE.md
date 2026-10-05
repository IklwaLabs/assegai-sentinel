# Architecture

Iklwa Sentinel is a local-first network visibility, monitoring and threat detection
platform. This document records the architectural decisions that constrain how the
code is written. It is the reference for boundaries; if code and this document
disagree, one of them is a bug.

## 1. Product abstraction

```
Packet -> Flow -> Context -> Detection -> Alert -> Incident
```

- **Packets are evidence.** They are decoded, counted and optionally sampled, but never
  the primary unit rendered to the user.
- **Flows are the primary unit.** Every user-facing view (Connections, Applications,
  Devices, traffic charts) is derived from aggregated flow state.
- **Context** is enrichment: process, application, domain, service, ASN, country.
- **Detections** are deterministic, explainable evaluations over normalized events.
- **Alerts** are user-facing records that carry evidence and a recommendation.
- **Incidents** correlate alerts over time, device, process and destination.

## 2. Crate map

Dependencies point strictly downward. A crate never imports a crate that depends on it.

```
                     sentinel-api            (DTOs + command/event contract)
                          |
                     sentinel-core           (pipeline orchestration, engine session)
        ------------------|------------------
        |                 |                 |
sentinel-capture   sentinel-flow      sentinel-storage
        |                 |                 |
        \_____________sentinel-parser______/
                          |
                   sentinel-platform      (OS interface discovery, paths, capabilities)
                          |
                   sentinel-common         (errors, time, config, normalized types)
```

| Crate | Responsibility | Must not do |
| --- | --- | --- |
| `sentinel-common` | Typed errors, clock, normalized network types, config schema, engine metrics | Touch the OS, depend on other Sentinel crates |
| `sentinel-platform` | Interface enumeration, per-OS enrichment, data/log/config paths, capability probing | Parse packets, own business state |
| `sentinel-parser` | Pure, allocation-conscious packet decoding to `NormalizedPacket` | Capture, persist, or hold state between packets |
| `sentinel-capture` | `CaptureProvider` trait + Npcap/libpcap adapters, offline PCAP source, bounded ingress queue | Analyze packets |
| `sentinel-flow` | Bidirectional flow keying, flow table with idle eviction, traffic aggregation | Persist or detect |
| `sentinel-storage` | SQLite schema, migrations, batched writer thread, retention | Decide what a flow is |
| `sentinel-core` | Wires capture -> parse -> flow -> aggregate -> storage, owns engine session state | Contain parsing or SQL details |
| `sentinel-api` | Serde DTOs, `SentinelCommand`, `SentinelEvent`, user-facing error mapping | Perform security analysis |

Additional crates (`sentinel-protocols`, `sentinel-device`, `sentinel-process`,
`sentinel-detection`, `sentinel-threat-intel`, `sentinel-risk`, `sentinel-reporting`)
are introduced by the milestone that needs them, per `ROADMAP.md`. They are
deliberately absent now: an empty crate is a placeholder, and placeholders are
treated as a defect.

## 3. Packet pipeline

```
CaptureSource (pcap live | pcap file)
  -> bounded ingress queue  (drop counter, never blocking)
  -> PacketDecoder          (frame validation, L2..L4)
  -> FlowEngine             (normalize key, update counters, TTL evict)
  -> TrafficAggregator      (1s ring buckets, protocol totals)
  -> StorageSink            (batched writer thread)
  -> EventBroadcaster       (throttled UI updates)
```

Rules that the pipeline must always hold:

1. **Bounded queues with explicit loss accounting.** The capture thread never blocks on
   a slow consumer. Overflow increments `packets_dropped`; the number is surfaced in
   the UI and the CLI rather than silently discarded.
2. **Single owner for mutable state.** The flow table, aggregator and storage sink are
   owned by one engine task. Concurrency is expressed by channels, not shared locks.
3. **Capture thread is not a Tokio task.** `libpcap` reads block; it runs on a dedicated
   OS thread and publishes into an async bounded channel with `try_send`.
4. **Decode is a pure function.** `PacketDecoder::decode` takes bytes and returns a
   normalized packet. It holds no state, so offline PCAP analysis and live capture share
   the exact same code path.
5. **No payload retention.** Payload lengths and metadata are kept; payload bytes are
   not, unless a bounded evidence sample is explicitly enabled.

## 4. Concurrency model

One engine thread per session (`sentinel-core/src/session.rs`):

- owns the flow table, aggregator, storage writer and event broadcaster
- receives `EngineRequest` over an mpsc channel and replies over a oneshot channel
- consumes decoded packets from the ingress queue
- broadcasts `SentinelEvent` to any number of subscribers

The API layer (Tauri commands, CLI, future remote sensor) is a thin request/response
client. It holds no analysis state, which keeps the future `sentinel-server` boundary
a transport change rather than a rewrite.

UI updates are throttled (default 4 Hz) and coalesced. React never receives individual
packets; it receives aggregate snapshots and aggregate diffs.

## 5. Storage model

SQLite in WAL mode, one writer thread, transactions per batch.

Tables in migration `0001`: `settings`, `interfaces`, `flows`, `traffic_samples`.

Design decisions:

- Migrations are plain SQL files embedded at compile time and applied in order inside a
  transaction, tracked in `schema_migrations`. No runtime migration framework.
- Flow history is retained per `RetentionPolicy` (24h / 7d / 30d / 90d / custom). The
  cleanup job runs at session start and then hourly.
- Aggregated samples are coarse on purpose. Storing every packet or every flow update
  is explicitly rejected; the flow table is a working set that is compacted on flush.
- No raw SQL string construction anywhere. All statements are static and bound through
  `rusqlite` parameters.

## 6. Platform abstraction

```rust
pub trait CaptureProvider: Send {
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>, CaptureError>;
    fn open(&mut self, interface: &NetworkInterface) -> Result<(), CaptureError>;
    fn close(&mut self) -> Result<(), CaptureError>;
    fn stats(&self) -> CaptureStats;
}
```

- **Windows**: Npcap via `pcap`. Capture requires an elevated process. Loopback capture
  is surfaced as a normal interface because Npcap installs one.
- **Linux**: libpcap; `CAP_NET_RAW`/`CAP_NET_ADMIN` or membership in the `pcap` group.
  Optional eBPF enrichment is a future feature, not a rewrite.
- **macOS**: libpcap/BPF; `/dev/bpf*` access needs `sudo` or the `access_bpf` group.
- **Android**: `VpnService` -> TUN -> Kotlin bridge -> `RawPacket` stream -> same decoder
  and flow engine. The capture adapter is the only Android-specific part; the analysis
  core is shared.

Interface enumeration is always two-step and OS-specific enrichment lives in
`sentinel-platform/src/<os>/`: the `pcap` device list provides the portable baseline
(so the same list that can actually be captured is what the user sees), and the OS
module adds operstate, friendly names, loopback/wireless classification and capability
hints. No `if` statements on `cfg(target_os)` exist outside `sentinel-platform`.

## 7. Error handling contract

- Libraries return typed `thiserror` enums (`CaptureError`, `DecodeError`,
  `StorageError`, `FlowError`, `PlatformError`).
- Each error type implements `UserFacing`, producing a `UserMessage`
  (`title`, `summary`, `hint[]`, `details`) so the UI shows:

  > Sentinel could not access this network interface. Packet capture permission is
  > missing.

  with the technical detail available behind a "Details" disclosure.
- `unwrap()`/`expect()` are not used outside tests and genuinely unreachable
  initialization where the invariant is documented inline.
- Application entry points use `anyhow` only for start-up wiring.

## 8. Security posture of the product itself

- Local-first: the core never requires network access. External threat-intel providers
  are optional and off by default; private and LAN addresses are never submitted
  anywhere.
- Least privilege: Sentinel requests only packet-capture capability, and the UI states
  plainly why. Response actions (block, quarantine, terminate) live in an opt-in module
  and never run automatically.
- Secrets: provider API keys live in the OS keychain when a keychain backend exists;
  otherwise they are explicitly reported as stored in a local config file. They are
  never logged, never exported with reports.
- Dependencies are audited (`cargo audit`) and unpinned-transitive surprises are
  reviewed in CI.
- Update and release channels are documented in `SECURITY.md`.

## 9. Frontend contract

The React app is a renderer and a command sender. It performs no analysis, holds no
authoritative state, and makes no network calls of its own.

```
Rust (engine session)  --invoke-->  commands (request/response)
Rust (event stream)    --listen--> throttled aggregate snapshots
```

Rules enforced by review and lint:

- `strict: true`, no `any` without a documented reason.
- Feature-oriented modules under `src/features/*`; no file above ~400 lines.
- Tables are virtualized; charts aggregate; no per-packet rendering.
- Styling is a small token set (see `apps/desktop/frontend/src/app/tokens.css`) with one
  restrained brand accent. Severity is never encoded by color alone.

## 10. Decisions log

| # | Decision | Rationale | Revisit when |
| --- | --- | --- | --- |
| D1 | `rusqlite` with bundled SQLite over `sqlx` | Synchronous, single-writer batching is simpler to reason about than an async pool for a single local database; fewer build-time dependencies | A remote/multi-writer store is ever needed |
| D2 | `pcap` crate for Windows/Linux/macOS | One well-maintained binding over Npcap/libpcap/BPF; identical API surface reduces platform code | Android TUN requires a different adapter (already the case) |
| D3 | Flow keys normalized bidirectionally at construction | Connections are inherently bidirectional; ordering in the key makes aggregation correct without per-packet state | Never |
| D4 | Flow state owned by one engine task | Avoids lock contention in the hot path and keeps ownership obvious | Multi-threaded decoding is required for >100k pps |
| D5 | Migrations embedded as SQL files, not a runtime framework | Reproducible builds, reviewable diffs, no extra dependency | Never |
| D6 | Config is plain typed data with `serde` defaults; persistence lives in the platform layer | Keeps `sentinel-common` free of OS dependencies and makes config testable | Never |
| D7 | No telemetry, no crash upload, no account | Product requirement and the trust differentiator | Cloud sync ships as opt-in |
| D8 | Frontend owns no security logic | Keeps analysis testable in Rust and portable to CLI/sensor | Never |

## 11. Anti-goals

Explicitly rejected, so they are not "accidentally" reintroduced:

- Global mutable singletons or a god object holding all subsystems.
- A global event bus crate. Events are dispatched by the engine broadcaster that already
  owns them.
- Wrappers whose only purpose is to look layered.
- Hand-written protocol parsers for L2-L4; `etherparse` is used.
- Feature flags pretending an unimplemented feature works.