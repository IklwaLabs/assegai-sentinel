# Platform Support

What Sentinel does on each platform, what it needs, and where the differences are. `sentinel
doctor` reports all of this for the machine you are on.

## Summary

| | Windows | Linux | macOS | Android |
| --- | --- | --- | --- | --- |
| Capture driver | Npcap (WinPcap compatible) | libpcap | BPF framework | `Tun2Socks` |
| Privilege needed | Administrator | `CAP_NET_RAW` or root | `access_bpcap` group | app-private VPN |
| Live capture | Yes | Yes | Yes | Not implemented |
| Interface enumeration | Yes | Yes | Yes | Yes |
| PCAP analysis | Yes | Yes | Yes | Yes |
| Loopback capture | Dedicated adapter | Yes | Limited | N/A |
| Desktop app | Yes | Yes | Yes | No |
| Release artifact | `.exe`, `.msi` | `.deb`, `.AppImage` | `.dmg`, `.app` | `.apk` |

## Getting a build

Releases are cut by `.github/workflows/release.yml`, which builds each platform on its own
runner. That is deliberate: a Tauri bundle needs the *host* platform's webview, packaging and
code-signing tools, and macOS cannot be built from Windows or Linux at all. Adding Rust targets is
easy; adding the surrounding toolchain is not.

```bash
git tag v0.1.0 && git push origin v0.1.0    # triggers the release matrix
```

Or dispatch the workflow manually for an existing tag.

To build one platform yourself, see the table above for its capture driver and
[DEVELOPMENT.md](../DEVELOPMENT.md) for the shared prerequisites.

Two build details worth knowing:

- **macOS bundles are unsigned.** Gatekeeper will refuse them until the user right-clicks and
  chooses Open, or clears the quarantine flag. Notarisation needs an Apple developer account.
- **Android ships as an APK, not an AAB.** An AAB can only be uploaded through Play Console and
  cannot be side-loaded, which makes it useless for verifying a build. Live capture is not
  implemented, so that build ships the interface and offline PCAP analysis only.

Only `crates/sentinel-platform` contains `cfg(target_os)`. Every other crate consumes normalized
types, which is why the pipeline, decoder, flow engine and storage are identical on all of them.

## Windows

**Driver.** [Npcap](https://npcap.com/), in place of or alongside WinPcap. Npcap's installer
puts `wpcap.dll` and `Packet.dll` into `System32`.

**Linking.** Npcap's runtime does not install `wpcap.lib`, so a machine with the runtime but not
the SDK can capture but cannot link. Install the SDK (recommended, and what CI does), point
`IKLWA_PCAP_LIB` at a `wpcap.lib`, or synthesise one from the installed DLL's export table with
`tools/make-wpcap-lib.ps1`. See [DEVELOPMENT.md](../DEVELOPMENT.md#the-windows-linking-problem).

**Privileges.** Reading frames requires an elevated token. Sentinel reports `notElevated` in
`sentinel doctor` rather than failing at capture time with a driver error code.

**Loopback.** Npcap exposes loopback traffic through a separate loopback adapter, available only
when installed in full mode. Sentinel lists it and says which mode is required, rather than
showing an adapter that captures nothing.

**Interfaces.** Enumerated via `pcap_findalldevs`, classified as wired, wireless, loopback,
tunnel or virtual, with addresses from `GetAdaptersAddresses`. Capture readiness is per interface:
an adapter that is down, or that the driver refuses, is listed with the reason.

## Linux

**Driver.** `libpcap-dev` (Debian, Ubuntu) or `libpcap-devel` (Fedora, RHEL). Linking is
automatic; no configuration is needed.

**Privileges.** Either run as root, or grant the binary `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/sentinel
```

This is preferable to running the whole application as root, and is what Sentinel's guidance
recommends.

**Loopback.** Supported directly.

**Interfaces.** Enumerated via `pcap_findalldevs`. Wireless and virtual interfaces are
classified; some virtual interfaces (Docker bridges, VPN tunnels) cannot be captured even when
listed, and Sentinel says so instead of offering them.

## macOS

**Driver.** None to install. The BPF framework is part of the base system, and linking is
automatic.

**Privileges.** The process must belong to the `access_bpcap` group. Membership is granted at
install time on some paths and must be arranged by an administrator otherwise. Sentinel reports
this through its privilege state.

**Loopback.** Limited. `lo0` is visible but does not carry traffic in a way that is useful for
network monitoring, so Sentinel deprioritises it when choosing an interface automatically.

## Android

**Status.** Interface enumeration and PCAP analysis work. Live capture is **not implemented** and
is the main outstanding platform work; the release build reports it as unavailable rather than
failing at runtime.

**Approach.** `Tun2Socks`. The app runs a userspace TCP/IP stack over a VPN slot the app itself
owns, which routes traffic through Sentinel's own capture point. This is the only approach that
does not require root, and it is how most Android network monitors work.

**Implications to plan for.** Battery: a userspace stack is expensive, so capture must be
explicit and bounded. Storage: mobile devices have little room, so retention defaults will be
shorter. Background execution: Android restricts long-running capture, which constrains what a
session can promise.

**Why the architecture already allows it.** Because `sentinel-platform` normalizes every platform
behind `NetworkInterface`, `Capabilities` and `AppPaths`, a `Tun2Socks` backend is one more
`CaptureProvider` implementation. The decoder, flow engine, aggregator and storage need no
changes, and neither does the API contract or either frontend.

## Adding a platform

1. Add `crates/sentinel-platform/src/os/<name>.rs`, implementing the same interface as the
   others: interfaces, capabilities, privilege state.
2. Extend the `cfg` dispatch in `sentinel-platform/src/os/mod.rs`. It should be the only
   `cfg(target_os)` added.
3. Add paths for the data, config, log and export directories. Read them from the platform's own
   conventions, not from an environment variable a previous platform happened to use.
4. Add a `CaptureProvider` in `sentinel-capture` if the driver is not libpcap.
5. Map every failure onto the existing `CaptureError` variants. Do not introduce a parallel
   error type; the user-facing message is built once, and a second path would diverge from it.
6. Add tests that do not require the platform: queue behaviour, error classification and config
   translation are all testable without hardware.

## What "supported" means here

A platform is supported when Sentinel can enumerate interfaces, capture from a selected one,
analyse a PCAP file, and store results — on that platform, without special-casing the pipeline.

It is *not* supported when the code compiles but produces misleading results. An interface listed
as capturable that captures nothing, or a loopback adapter shown without explanation of why it is
empty, is worse than an honest refusal, and Sentinel treats it as a bug.