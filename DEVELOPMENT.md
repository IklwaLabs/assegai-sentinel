# Development

## Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | 1.95 or newer | `rust-version` in the root `Cargo.toml` is the real floor. Edition 2024. |
| Node.js | 20 or newer | Only the desktop frontend needs it. |
| npm | 10 or newer | Ships with Node 20+. |
| C toolchain | current | Needed by `rusqlite` (bundled SQLite) and `pcap`. |
| Capture driver | see below | Needed to build and to capture. |

### Capture driver per platform

| Platform | Install | Linking |
| --- | --- | --- |
| Windows | [Npcap](https://npcap.com/) | The **SDK** is needed for `wpcap.lib`. See below. |
| Linux | `apt install libpcap-dev`, `dnf install libpcap-devel` | Automatic. |
| macOS | Built in | Automatic, via the BPF framework. |

## The Windows linking problem

Npcap's installer puts `wpcap.dll` and `Packet.dll` into `System32` but does **not** install
`wpcap.lib`. Installing only the runtime therefore leaves a machine that can capture but cannot
link. Two supported resolutions:

**1. Install the Npcap SDK (recommended).** Extract it anywhere; the build script searches the
standard `Program Files\Npcap-sdk\Lib` locations on its own and needs no configuration. This is
what CI does.

**2. Point `IKLWA_PCAP_LIB` at a `wpcap.lib`.** Set it in your shell, or copy
`.cargo/config.local.toml.example` to `.cargo/config.local.toml` and set it there. The
git-ignored local file is the right place for a machine-specific absolute path.

A third option exists for machines that cannot install the SDK:

```powershell
# Synthesises wpcap.lib from the installed wpcap.dll's export table.
.\tools\make-wpcap-lib.ps1
$env:IKLWA_PCAP_LIB = "$env:LOCALAPPDATA\IklwaDevTools\pcap"
```

This is a local build aid, not part of the product. It reads the PE export table of the
already-installed `wpcap.dll` and emits an import library, which is enough to link against a DLL
whose exports are unchanged. Do not ship this library; install the SDK for anything you
distribute.

If no `wpcap.lib` can be found, the build succeeds but emits a warning explaining what to do.
That is deliberate: a warning with instructions is more useful than a link error with a path in
it.

## Running

```bash
# Everything
cargo build
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# CLI
cargo run -p sentinel-cli -- doctor
cargo run -p sentinel-cli -- interfaces
cargo run -p sentinel-cli -- capture --interface <id> --duration 30
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap
cargo run -p sentinel-fixtures -- fixtures/detection-traffic.pcap --detections
cargo run -p sentinel-cli -- analyze fixtures/detection-traffic.pcap
cargo run -p sentinel-cli -- export --json --limit 100

# Desktop
cd apps/desktop/frontend && npm install && npm run typecheck && npm run build
cargo build --release -p sentinel-desktop --features custom-protocol
./target/release/sentinel-desktop
```

`cargo fmt` needs nightly for the `imports_granularity` and `group_imports` options in
`rustfmt.toml`. On stable it warns and applies the remaining options; that is fine, and CI runs
the stable subset.

### `custom-protocol` is not optional

`cargo build -p sentinel-desktop` produces a binary that opens a **black window**. No error, no
log line, just an empty window — because the build lacked Tauri's `custom-protocol` feature and
therefore loaded `devUrl` (`http://localhost:1420`) instead of the assets embedded in the
executable. With no Vite dev server running, that page never resolves.

Use `tauri dev` for development, and `--features custom-protocol` for anything you intend to
run or ship. `tauri build` passes the feature itself.

### Diagnosing a blank window

If the window is black or empty, the frontend failed to load. Rather than guess, ask WebView2
what URL it actually fetched:

```powershell
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9333"
.\target\release\sentinel-desktop.exe

# In a second shell:
(Invoke-WebRequest http://127.0.0.1:9333/json/list).Content
```

`http://localhost:1420/` means `custom-protocol` is missing. A `tauri://localhost/` URL with a
blank page means a console error, and commands failing with an unrecognised error almost always
mean a missing entry in `capabilities/default.json` — Tauri 2 denies every capability that is
not explicitly granted.

## Layout and where code belongs

Read [ARCHITECTURE.md](ARCHITECTURE.md) before adding anything. The short version:

- **`crates/sentinel-platform`** is the only crate allowed to contain `cfg(target_os)`. Every
  other crate consumes normalized types. If you need a platform fact, add it there.
- **`crates/sentinel-common`** holds shared types and has no dependencies. No logic belongs
  here that is not shared.
- **`crates/sentinel-parser`** owns decoding. It must be pure: a frame in, a
  `NormalizedPacket` or a counted error out.
- **`crates/sentinel-flow`** owns flow identity and aggregation. It must not know about time of
  day or the filesystem.
- **`crates/sentinel-storage`** owns persistence. Every write statement is defined once in
  `statements.rs` and used by both the direct `Database` methods and the writer thread.
- **`crates/sentinel-core`** owns the engine task and the pipeline. One task owns all mutable
  analysis state; if you find yourself wanting a lock, the design is telling you something.
- **`crates/sentinel-api`** is the contract. The frontend does no analysis.
- **`apps/`** contains only clients.

Dependencies point inward. `platform` and `common` know nothing; `api` knows the engine; the
apps know `api`. Nothing depends on an app.

## Testing

```bash
cargo test                        # everything
cargo test -p sentinel-flow       # one crate
cargo test --test offline_pipeline # one integration test target
cargo test -- --nocapture         # show stdout, useful for the PCAP tests
```

Tests must encode real behaviour. A test that documents how the system actually behaves —
canonical endpoint ordering, retention deleting strictly-older rows, a portless IPv6 address
parsing as an address rather than as address-and-port — is valuable. A test written to match
whatever the code happens to do is not; if a test fails, first decide which one is wrong.

Golden PCAP fixtures are generated, not committed as binaries, so their contents are reviewable
in source: `crates/sentinel-parser/src/fixtures.rs` builds them and
`tools/fixtures` writes a demo capture.

## Frontend

```bash
cd apps/desktop/frontend
npm run typecheck     # tsc --noEmit
npm run lint          # eslint, zero warnings tolerated
npm run format        # prettier
npm run dev           # vite dev server on 1420
npm run build         # typecheck + production bundle
```

The TypeScript types in `packages/types` mirror the Rust contract by hand. When you change a
serializable type on the Rust side, change it here in the same commit, and change the
`rename_all` casing to match. They are not generated, so the mirroring is a deliberate act.

The lint config is type-aware and treats `any` as an error. When ECharts' public types are
narrower than the values it actually passes to a callback, narrow the payload once at the
boundary with a named local interface rather than casting at every access.

## Adding a capture backend

1. Implement `CaptureProvider` in `crates/sentinel-capture`.
2. Put the `cfg(target_os)` selection in `crates/sentinel-capture`, not in the core.
3. Map failures onto the existing `CaptureError` variants. Do not invent a parallel error type;
   the user-facing message is built once, in one place.
4. Report driver-level drops through `CaptureStats`. A silent loss is worse than no capture.
5. Add tests that do not require the driver: the queue, the classification and the config
   translation are all testable without hardware.

## Adding a detector

Detection lives in `crates/sentinel-detect`; the engine only calls it. To add a detector:

1. Create a module with a struct that has `new`, `reset` and
   `observe(&NormalizedPacket) -> Option<Observation>`. Keep it free of I/O and of the wall
   clock: time is the packet's own timestamp, which is what makes captures replayable.
2. Build an `Observation` with a stable identity, a one-line title, a plain-language detail,
   the evidence behind it, and the advice a person should follow. Severity (impact if real) and
   confidence (how sure the detector is) are separate fields.
3. Add the module to `DetectionEngine` in `lib.rs`, including `reset`.
4. If it introduces a new `FindingKind`, add the variant and its `as_str`/`parse` pair. Stored
   rows use the string, so the pair must round-trip; an unreadable identifier is reported as
   corruption rather than defaulted.
5. Bound every table. A spoofed source address is free, and an attacker can use that to make a
   detector allocate without limit.
6. Test the positive case, the negative case, the boundary, and a benign look-alike. Then add
   an integration test in `crates/sentinel-core/tests/offline_pipeline.rs` if the detector can
   be reached from a capture file.

Emit on threshold crossing, not on every packet after it. Further observations update the same
finding rather than producing new ones.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test
cd apps/desktop/frontend && npm run typecheck && npm run lint && npm run build
```

All five must pass. If a lint is wrong rather than the code, fix the lint and say why in the
commit; do not add a blanket `allow`.