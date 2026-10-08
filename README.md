# Assegai Sentinel

Local-first network visibility and threat detection. Sentinel watches the traffic on your
machine, reconstructs the connections that carry it, stores what it finds in a local database,
and tells you what is happening — without an account, without a cloud service, and without
sending anything anywhere.

```text
  network  ->  capture  ->  decode  ->  flow engine  ->  detection  ->  SQLite  ->  interface
              (Npcap)     (L2-L4)    (bidirectional)   (explainable)  (local)     (CLI + desktop)
```

## What it does today

- **Enumerates real capture interfaces** through Npcap on Windows, libpcap on Linux and macOS.
- **Captures live traffic** from a selected adapter, in a dedicated thread, with backpressure
  that is *counted* rather than hidden.
- **Decodes Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP and ICMP** with an own bounds-checked
  decoder, so truncation and IP fragmentation are handled explicitly instead of guessed at.
- **Reconstructs bidirectional flows** keyed on a canonically ordered endpoint pair, with
  initiator detection from port roles.
- **Aggregates traffic** into one-second buckets for the chart, in both directions.
- **Analyses PCAP files offline through the same pipeline** as live capture, so results match.
- **Reports packet loss** from the driver, the ingress queue and the decoder separately, and
  says so on every surface. Incomplete data is labelled as incomplete.
- **Stores flows in SQLite** in one batched writer thread, with configurable retention.

Not yet implemented, and deliberately absent from the interface rather than faked: threat rules,
process attribution, device inventory, DNS correlation, and desktop capture-file import.

## Why it is built this way

- **The engine owns every decision.** The CLI and the desktop app are both thin clients over
  one engine, so they cannot disagree about what your network is doing. The frontend performs
  no analysis.
- **No network access, ever.** There is no code path that opens an outbound connection. See
  [SECURITY.md](SECURITY.md).
- **One owner of mutable state.** A single task owns the flow table, so the packet path needs no
  locks. See [ARCHITECTURE.md](ARCHITECTURE.md).
- **Honest failure.** Every error carries a user-facing explanation and concrete next steps.
  Raw driver strings are never the only thing a user sees.

## Repository layout

| Path | What lives there |
| --- | --- |
| `crates/sentinel-common` | Shared types: packets, config, metrics, clock, errors. No logic. |
| `crates/sentinel-platform` | The only crate with `cfg(target_os)`. Paths, capabilities, settings. |
| `crates/sentinel-parser` | L2–L4 decoder and a dependency-free PCAP reader/writer. |
| `crates/sentinel-flow` | Flow keys, the flow table, traffic aggregation. |
| `crates/sentinel-storage` | SQLite schema, migrations, batched writer, retention. |
| `crates/sentinel-capture` | Capture backends and the bounded ingress queue. |
| `crates/sentinel-core` | The engine task and the pipeline that stitches the above together. |
| `crates/sentinel-api` | The command and event contract every frontend uses. |
| `apps/cli` | The `sentinel` command line interface. |
| `apps/desktop` | The Tauri + React desktop application. |
| `tools/fixtures` | Generates deterministic PCAP files for demos and tests. |
| `site` | The download page, generated from `site/release-manifest.json`. |

Dependencies point inward: `platform` and `common` know about nothing; `api` knows about the
engine; the apps know about `api`. Nothing depends on an app.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for what a change should look like, and
[CONTRIBUTORS.md](CONTRIBUTORS.md) for who builds this.

## Documentation

**[`docs/Sentinel-Reference.pdf`](docs/Sentinel-Reference.pdf)** is the whole product in one
document — architecture, how to run it, how to control it, troubleshooting. Start there.

| Document | Covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate map, concurrency, storage, design decisions |
| [ROADMAP.md](ROADMAP.md) | What is built, what is next |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Prerequisites, running, testing, conventions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | What a contribution should look like |
| [SECURITY.md](SECURITY.md) | What Sentinel does with your data, and how to report a vulnerability |
| [docs/PACKET_PIPELINE.md](docs/PACKET_PIPELINE.md) | How a frame becomes a connection, and where data can be lost |
| [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | The detection design, and why it is not implemented yet |
| [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) | Per-platform drivers, privileges and limitations |
| [docs/MATURITY-ANALYSIS.md](docs/MATURITY-ANALYSIS.md) | What mature NSM tools have that Sentinel lacks, and the proposed order to build it |

## Downloading

**[`site/index.html`](site/index.html)** is the download page for the IklwaLabs website: one
self-contained HTML file, no build step and no runtime dependency, ready to serve as-is or drop
onto a static host.

It is generated from `site/release-manifest.json` by `tools/generate-download-site.py`, the same
arrangement as the PDF: the manifest holds the facts, the generator reads them back out of the
code to check them, and CI fails if the committed page drifts from the manifest.

```bash
python tools/generate-download-site.py           # write site/index.html
python tools/generate-download-site.py --check   # fail if it is stale, for CI
```

While no release is published the page says so in plain language and shows the buttons disabled
with their real filenames, rather than offering links that would 404. Flipping
`release.published` in the manifest once the artifacts exist turns them into live links.

## Building from source

You need Rust 1.95 or newer, Node.js 20 or newer, and a packet capture driver:

| Platform | Driver |
| --- | --- |
| Windows | [Npcap](https://npcap.com/), with the SDK for linking |
| Linux | `libpcap-dev` |
| macOS | Built in (BPF framework) |

```bash
# Rust workspace: builds, tests and lints everything
cargo build
cargo test
cargo clippy --workspace --all-targets -- -D warnings

# CLI
cargo run -p sentinel-cli -- doctor      # is capture possible here?
cargo run -p sentinel-cli -- interfaces
cargo run -p sentinel-cli -- capture --duration 30
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap

# Desktop application. The custom-protocol feature is required: without it the binary
# opens a black window, because it looks for the Vite dev server instead of the
# assets embedded in the executable.
cd apps/desktop/frontend && npm install
cargo build --release -p sentinel-desktop --features custom-protocol
./target/release/sentinel-desktop
```

Full prerequisites, including how to build on a machine that has Npcap's runtime but not its
SDK, are in [DEVELOPMENT.md](DEVELOPMENT.md).

Packet capture requires elevated privileges on most systems. `sentinel doctor` reports whether
capture is possible in the current process and, when it is not, exactly what to do about it.

## Generating a demo capture

```bash
cargo run -p sentinel-fixtures -- fixtures/demo-traffic.pcap
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap
```

The fixture is generated rather than committed as a binary, so its contents are reviewable in
source: a TLS-shaped exchange, DNS with a response, an unanswered query, ICMP, ARP, a VLAN
frame, a non-initial IPv4 fragment, a malformed frame, and two connections to unexpected ports.

## License

Apache-2.0. See [LICENSE](LICENSE).