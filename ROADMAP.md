# Roadmap

Milestones are ordered by the product priority rule: correctness, architecture,
stability, security, performance, usability, then feature depth. A milestone is only
complete when it is formatted, linted, tested and documented.

Legend: `[x]` done, `[~]` in progress, `[ ]` not started.

---

## v0.1 — Foundational monitoring engine (current milestone)

Goal: a correct, tested capture -> decode -> flow -> persist -> render loop, plus a
desktop shell that starts and stops monitoring honestly.

- [x] Rust workspace with strict lint and formatting policy
- [x] `sentinel-common`: typed errors, clock, normalized network types, config schema,
      engine metrics
- [x] `sentinel-platform`: interface discovery, per-OS enrichment, app paths, capability probe
- [x] `sentinel-parser`: Ethernet (+VLAN), ARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP
- [x] `sentinel-capture`: `CaptureProvider`, live pcap adapter, offline PCAP source,
      bounded ingress queue with drop accounting
- [x] `sentinel-flow`: bidirectional flow key, flow table with idle eviction, traffic aggregation
- [x] `sentinel-storage`: SQLite schema + migrations, batched writer, retention job
- [x] `sentinel-core`: engine session, request/response API, throttled event broadcast
- [x] `sentinel-api`: DTOs, commands, events, user-facing error mapping
- [x] `apps/cli`: `interfaces`, `capture`, `status`, `analyze`, `export`, `doctor`
- [x] `apps/desktop`: Tauri shell + React/TS frontend (first-run, overview, connections,
      traffic chart, settings, diagnostics)
- [x] Golden PCAP fixtures + integration tests (`pcap -> flows -> alerts-ready state`)
- [x] Documentation: README, ARCHITECTURE, DEVELOPMENT, PACKET_PIPELINE, PLATFORM_SUPPORT,
      DETECTION_ENGINE, SECURITY, CONTRIBUTING

Acceptance criteria:

1. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass.
2. Frontend passes `tsc --noEmit` and `vite build`.
3. `sentinel analyze <pcap>` and `sentinel capture` produce identical flow shapes from the
   same decoder.
4. No UI code performs analysis; no Sentinel crate contains `cfg(target_os)` outside
   `sentinel-platform`.
5. Errors surfaced in the UI are actionable, with technical detail behind "Details".

Known limitations are recorded in `README.md` (section: Limitations of v0.1).

---

## v0.2 — Visibility (devices, processes, DNS, applications)

- [x] `sentinel-response`: consent gate with a named authorisation, ARP cache poisoning
      detection, gratuitous-ARP repair, durable audit trail. Off by default; detection works
      regardless. See `SECURITY.md` for what is and is not transmitted.
- [ ] `sentinel-protocols`: DNS, DHCP, mDNS, SSDP, NTP, HTTP metadata, TLS client hello + certificate metadata, QUIC initial metadata
- [ ] `sentinel-process`: per-OS connection-to-process resolvers (Windows IP Helper, Linux `/proc`, macOS libproc) behind `ProcessResolver`
- [ ] `sentinel-device`: LAN inventory, ARP/DHCP/mDNS/SSDP/ND observation, MAC OUI vendor lookup, confidence levels
- [ ] Hostname enrichment and cached resolution with TTL
- [ ] Connections page: search, filter, sort, pause, export, pin, side panel
- [ ] Applications page and Devices page
- [ ] DNS page with query/response history and per-source filtering
- [ ] Exports: CSV and JSON for connections, devices, DNS, Zeek-compatible (`conn.log`,
      `dns.log`, `ssl.log`, `notice.log` field names)
- [ ] PCAPNG reader. Pcapng is Wireshark's default format since roughly 2016, and most shared
      evidence arrives in it; today Sentinel refuses it and tells the user to run `editcap`.
- [ ] Storage rollups: `traffic_samples` is one row per second by design (31.5M rows/year).
      Add minute and hourly tables and prune the raw one behind them, or long-term retention
      is not viable.
- [ ] Rolling packet buffer with capture windows. Revisits the deliberate "raw packets are
      never stored" decision in `migrations/0001_initial.sql`. Rationale in
      `docs/MATURITY-ANALYSIS.md`.

### Known limits carried into v0.2

- **802.11 management frames are invisible.** The WiFi driver strips the 802.11 header before
  frames reach a packet socket, and management frames are never delivered to one. Sentinel
  therefore cannot detect an evil twin, a rogue access point, or a deauthentication flood, and
  does not attempt to interfere with access points. Seeing them needs monitor mode (Linux) or
  a native WiFi scanning API — a separate piece of work with privileges Sentinel does not
  request.
- **A single host's visibility.** Sentinel sees the traffic of the machine it runs on. It can
  report that this machine is being attacked, and by extension that the network is compromised.
  It cannot block an attacker from reaching other devices on the network.

---

## v0.3 — Security

- [ ] `sentinel-detection`: `Detector` trait, per-category detectors, explainable evidence
- [ ] Recon detectors: horizontal port scan, vertical port scan, host sweep, broad scan
- [ ] ARP detectors: conflicting MAC/IP mapping, gateway change, suspected spoofing
- [ ] `sentinel-threat-intel`: provider trait, local blocklist, imported IOC files, optional remote providers, cache, privacy filter for private/LAN addresses
- [ ] Behavioral detectors: beaconing, rare destination, unusual port/protocol, upload spike, destination fan-out
- [ ] `sentinel-risk`: centralized weight table, transparent scoring, explanations, severity bands
- [ ] Alerts: model, status workflow (new/acknowledged/investigating/resolved/false positive), explicit reversible suppression
- [ ] Threats, Alerts and Intelligence pages with "Why was this flagged?"

---

## v0.4 — Investigation

- [ ] Timeline view
- [ ] Incident correlation (device, process, destination, domain, temporal proximity)
- [ ] Evidence model and incident narrative
- [ ] `sentinel-reporting`: security summary, inventory, incident, PCAP, device, threat reports in PDF/CSV/JSON
- [ ] Network map with LAN/internet clustering and click-through
- [ ] Baselines: rolling windows per device and per application, deviation explanations, reset

---

## Android phase (after shared logic is stable)

- [ ] `VpnService` + TUN adapter in Kotlin
- [ ] JNI bridge streaming raw packets into the shared decoder
- [ ] Mobile UI: bottom navigation (Home, Activity, Apps, Threats, More), clear VPN status
- [ ] Battery-conscious sampling and wake-lock discipline
- [ ] Same parser, flow engine, detection and storage as desktop

---

## Later (architecture must permit, not require)

Suricata/eBPF/YARA integration, MISP, STIX/TAXII, remote sensors, `sentinel-server` +
`sentinel-web`, organization management, firewall automation, container and Kubernetes
visibility, IoT profiling, ML anomaly detection, plugin loading.

Local functionality must never depend on any of these existing.

---

## Milestone report template

Every milestone closes with:

```
Completed
Files changed
Architecture decisions
Tests run
Known limitations
Next milestone
```