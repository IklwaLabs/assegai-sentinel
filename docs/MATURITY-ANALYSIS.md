# Making Sentinel a Mature Network Security Tool

Research notes and a prioritised proposal. Written against `main` at `6bbe9bf`, with v0.1
shipped and CI green.

This is not a restatement of `ROADMAP.md`. That roadmap is unusually good — it sequences
correctly (visibility before detection, evidence before risk scoring), it is honest about
what is absent, and its "Later" list is well judged. What follows is only the delta: things
it omits, things it has ordered wrong, and one place where it contradicts a guarantee the
product makes in public.

---

## A bug to fix first: two config options that do nothing

Before any roadmap work. `sentinel-common::config::CaptureConfig` declares:

```rust
/// Enable payload retention where it is needed and safe.
pub capture_payload_samples: bool,
/// Redact local and LAN addresses in exported reports.
pub redact_local_addresses_in_exports: bool,
```

Across the entire repository — Rust, TypeScript, the PDF generator — these two fields are
**written and never read**. `sentinel export` opens the database and calls `recent_flows`
without loading config at all, so the redaction flag cannot possibly apply.

Consequence: a user who enables *"Redact local and LAN addresses in exported reports"* gets
exports containing their full RFC 1918 addressing, LAN topology and device IPs. The setting
promises the exact opposite of what it does. For a security tool whose selling point is
local-first data handling, that is the most damaging kind of bug: it fails open, silently,
on the one path where a user hands data to someone else.

The same is true of `capture_payload_samples`, which at least fails safe (it promises
retention it does not perform).

Two options: implement both, or delete both. Deleting is defensible for
`capture_payload_samples` until §1 lands. **`redact_local_addresses_in_exports` should be
implemented**, because it is a privacy control and its absence is a disclosure risk.

Whichever is chosen, the config surface should stop being able to describe behaviour the
product does not have. A field no code reads is documentation that lies.

---

## The strategic finding: evidence, not visibility

Sentinel stores **flows, one-second traffic samples, protocol totals, interfaces and
settings**. It stores no packets — and `migrations/0001_initial.sql` says so deliberately:

> *Flows are a working set, not a packet archive.*
> *Raw packets are never stored. There is deliberately no packets table.*

That was the right call for v0.1. It is also what currently separates Sentinel from a tool
you can hand to someone else after an incident.

Everything the roadmap plans — process attribution, device inventory, detections, timeline,
incident narrative — is derived from flow metadata. That is enough to say *"this machine
talked to that host"*. It is not enough to answer the only question that matters during an
incident: **"show me the traffic."**

Wireshark's entire value is packets. Zeek's is that packets are on disk *before* anyone
knows to look. When an alert fires at 14:32 and Sentinel holds flow rows, the investigation
stops at metadata permanently, and no amount of detection quality compensates.

Mature NDR products are built around exactly this: continuous rolling capture, with alerts
that *point at a window of already-buffered traffic*. When the alert fires you can attach the
evidence.

Recommendation: revisit the deliberate decision with this new evidence and promote rolling
capture to v0.2. It is more tractable than anything else here — you already own a correct,
tested `PcapWriter` in `sentinel-parser`, currently used only to generate golden fixtures.
Details in §1.

---

## 1. Rolling packet buffer with evidence windows

**What:** a bounded, continuously-written ring buffer of raw frames per session — PCAP on
disk — plus a `capture_windows` record created when something noteworthy happens. The alert,
the connection, and any later incident all reference the window instead of re-reading flows.

**Why it is cheap here:** `sentinel_parser::pcap::PcapWriter` already exists and is tested
against golden fixtures. This is a writer per session, a size cap, a rotation policy, and
retention.

**The design constraint that matters:** retention must be *time and size* bounded, and the UI
must always show the buffer's real state — bytes retained, oldest timestamp, frames dropped.
A truncated buffer presented as a complete one is worse than no buffer, and this codebase
already has that principle written down. Loss accounting is not optional here.

Note that this is also the natural home for `capture_payload_samples` — the option that
currently exists in config without an implementation.

---

## 2. PCAPNG support (a usability cliff, currently a hard refusal)

`PcapFileError::UnsupportedFormat` currently refuses PCAPNG and tells the user to run
`editcap -F pcap`. That is the right instinct — a different container must be handled
properly, not guessed at — but the outcome is bad:

PCAPNG has been Wireshark's default save format for roughly a decade. Most PCAPs shared in
tickets, threat reports and incident channels today are PCAPNG. A user dragging in real
evidence gets told to install Wireshark and learn a command line.

PCAPNG is also *not* just a different header. It is a sequence of typed blocks (Interface
Description, Enhanced Packet, Name Resolution, Decryption Secrets, custom blocks), multiple
interfaces per file, per-interface snaplen and timestamp resolution, and comments. It is a
small parser — comparable to the classic reader you already own — and it is a prerequisite
for being usable on real-world captures.

Recommendation: v0.2, alongside `sentinel-protocols`.

---

## 3. Zeek-compatible structured logs

The roadmap promises "Exports: CSV and JSON". What is missing is that the schema should be
**Zeek-compatible**, because that is the lingua franca of network security.

SOC runbooks, SIEM queries, threat-intel exchanges and half the public detection content
already speak `conn.log` / `dns.log` / `ssl.log` / `notice.log` field names. Emitting
`uid`, `id.orig_h`, `id.resp_h`, `proto`, `orig_bytes`, `resp_bytes`, `conn_state`,
`duration`, `query`, `answers`, `validation_status` means Sentinel output is usable by
people and tools that already exist, and that anything written against Zeek examples works
unchanged.

Cost is low — it is a serialisation format over data you already hold. Reach is high.

Recommendation: make the CSV/JSON exports Zeek-compatible, and ship `conn.log`, `dns.log`,
`ssl.log`, `notice.log` as the four v0.3 log types.

---

## 4. Flow export: NetFlow v5 and IPFIX

Also absent, and it is the missing *inbound* path.

Every other tool in this category either sends flow records to a collector or **receives**
them. Receiving matters more than sending: on a machine with a router, firewall or managed
switch, NetFlow/IPFIX gives you visibility of traffic you cannot see on the wire at all —
other VLANs, other subnets, other machines' sessions. For a tool that claims network
visibility, that is a large blind spot closed cheaply.

It is also well-specified (v5 is trivial; IPFIX is more work but bounded), well understood,
and it composes with §3 — both are "consume a standard schema and emit a standard schema".

---

## 5. TLS fingerprinting — with a hard honesty constraint

The roadmap says "TLS client hello + certificate metadata". It does not say **JA4/JA4S/JA4H**
(JA3/JA3S for legacy correlation), which is *the* technique for getting visibility into
encrypted traffic without decrypting it. This should be in v0.2's protocol work.

The constraint, and it is not optional: **a fingerprint is not an identity.** Research is
consistent on this. One JA3 hash was observed across four unrelated malware campaigns in the
same period, purely because they shared a TLS library. Browsers change, middleboxes
normalise, and corporate proxies reuse. The JA4 authors say plainly it must be treated as an
investigation aid and never as a standalone verdict or a blocking decision.

So: display fingerprints, count distinct fingerprints per host, show first-seen/last-seen,
and let novelty be the signal. Never render "malicious because JA4 = x".

---

## 6. Notification channels — a detector nobody is told about is not a detector

The roadmap models alerts and their status workflow well. It has no **delivery**.

An alert that lands in a local SQLite table while you are looking at something else is
invisible. Every mature tool has at minimum: desktop notification, and one machine-readable
sink. Given your no-network guarantee, the honest set is:

- desktop notification (local)
- Windows Event Log / syslog (local)
- an **export-to-file** sink the user points at their own tooling

No webhook to a remote URL — see §9.

---

## 7. Storage will not scale as planned

`traffic_samples` is one row per second — `sentinel-flow/src/aggregate.rs` is explicit that
it is "deliberately coarse: one bucket per second". That is 31.5M rows/year, forever, before
any flow table growth. Retention currently deletes rows; it does not compress them.

Mature deployments want months of trend data at second resolution and years at coarser
resolution. Add rollups: `traffic_samples_minute` and `traffic_samples_hourly`, written by
the same writer task, with the raw table pruned behind them. Do it in the same migration pass
as retention defaults, before there is data to migrate.

This is the one item on this list that gets *worse* the longer it is deferred.

---

## 8. Smaller gaps worth naming

| Gap | Note |
| --- | --- |
| **Capture filter** | You have `snaplen`, `promiscuous` and a `filter` in config, but no UI control and no per-session filter. Filter is a top-three usability feature for any capture tool — it is also the only way to make a noisy interface tractable on a busy machine. |
| **TCP connection state** | Zeek's `conn_state` (`S`, `SF`, `REJ`, `RSTO`…) needs a real TCP state machine. You have endpoint-pair flow keys; a state machine is what distinguishes a completed session from a half-open scan attempt, which is the basis of every scan detector in v0.3. |
| **Capture all interfaces** | One adapter per session. Aggregation across adapters is expected of a monitoring tool. |
| **Named profiles** | A saved capture job — interface, filter, snaplen, retention — is how anyone runs this more than once a week. |
| **Capture-loss surfacing** | You already count driver / queue / decoder loss separately. Make it visible in the UI *per session* with a reason, not only in aggregate. This is a credibility feature. |
| **Local diagnostics export** | No telemetry means no crash reporting. The substitute is a one-click "export diagnostics" bundle — config, versions, counters, recent logs — which must honour `redact_local_addresses_in_exports` once that option is actually implemented (see the bug at the top). |

---

## 9. A contradiction to resolve before v0.3

`SECURITY.md` states, as a headline guarantee:

> **Sentinel never opens an outbound network connection.** There is no HTTP client, no DNS
> resolver, no code path that constructs an outbound address.

`ROADMAP.md` v0.3 says:

> `sentinel-threat-intel`: … imported IOC files, **optional remote providers** …

and "Later" lists MISP, STIX/TAXII and `sentinel-server`.

These cannot both be true. If remote providers ever ship, the guarantee that differentiates
you from every cloud-dependent tool is gone — and that guarantee is, right now, a large part
of why an African SME or a bank in Dar es Salaam would deploy this at all.

Recommendation: decide it deliberately and write it down. My preference:

1. **v0.3 ships offline threat intel only** — local blocklist, user-imported IOC files. Keeps
   the guarantee absolute.
2. Remote fetching only ever happens in a *separate* optional component that is not built by
   default, whose existence is stated plainly in `SECURITY.md`, so the claim becomes
   "Sentinel Core never opens an outbound connection" rather than something fuzzier.
3. Whatever is chosen, update `SECURITY.md` and `ROADMAP.md` in the same commit so they
   cannot drift apart again.

---

## Proposed ordering

I would change v0.2 from *visibility-only* to **visibility + evidence**, on the grounds that
process attribution and device inventory are only worth having if there is evidence to
correlate them against.

**v0.2 — Evidence and visibility**
1. PCAPNG reader (removes the adoption cliff)
2. `sentinel-protocols`: DNS, DHCP, TLS+JA4 fingerprints, HTTP, mDNS/SSDP/NTP
3. Rolling packet buffer + `capture_windows`
4. `sentinel-process` (Windows first — IP Helper gives PID with no driver)
5. Capture filter + capture-all-interfaces in the UI
6. Storage rollups (minute/hour), shipped *with* retention defaults

**v0.3 — Detection, as already written**
7. TCP state machine, then recon detectors (they depend on it)
8. `sentinel-detection` + explainable evidence, one detector well before many poorly
9. Alerts + notification channels (desktop, Event Log, file sink)
10. Offline threat intel only — see §9

**v0.4** — investigation: timeline, correlation, reporting, baselines. Your existing plan,
now resting on real evidence rather than flow metadata.

---

## What I would deliberately *not* build

More decoders for their own sake. Protocol coverage has diminishing returns — what matters
is DNS and TLS, because those are where modern traffic actually goes. Breadth past that is
work that does not change a conclusion.

Also: a scoring number that claims to quantify risk. "Threat score 87/100" implies precision
nobody has. Banded severity with an explicit, inspectable evidence list is both more honest
and more useful. Your `sentinel-risk` design already says "transparent scoring" — hold that
line and resist compressing it to a single digit.