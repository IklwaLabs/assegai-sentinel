# The Detection Engine

Sentinel is a monitoring tool first and a threat detector second. This document explains what
that ordering means, what the engine actually detects today, and the rules it refuses to break.

## Status

The detection engine is implemented in `crates/sentinel-detect` and runs on every decoded
packet, before flow tracking. Findings are:

- raised once when a threshold is crossed, then updated in place as further observations arrive
- deduplicated by a stable identity, so one port scan is one finding rather than 20 000 alerts
- stored in SQLite (migration `0003`), bounded by the configured flow retention period
- shown in the desktop application under **Detect → Detections** and by `sentinel findings`
- included in every engine snapshot, with a count and an explicit
  `findingsSuppressed` value when the in-memory cap was reached

`riskScore` on a connection is still `null`. Risk scoring would blend severity and confidence
into one number, which this design deliberately avoids.

## Three separate judgements

A finding carries three facts, never collapsed into one score:

- **Severity** — how much damage the behaviour could cause *if it is real*. Critical, High,
  Medium, Low, Info.
- **Confidence** — how sure Sentinel is that the behaviour is real rather than normal traffic
  that happens to look similar. High, Medium, Low.
- **Advice** — what a person should do next, in plain language, written by the detector.

A port scan from outside the local network is High severity and High confidence. A large upload
is High severity and Medium confidence, because it might be ransomware staging and it might be
the nightly backup. Presenting both as "critical" would be dishonest about the second.

## Why detection runs before flow tracking

ARP has no flow identity. Its frames carry no IP connection to key on, so a detector wired into
the flow path would never see the one protocol whose finding is the most serious. The pipeline
therefore runs detection on every decoded packet, then excludes fragments and non-IP frames from
flow accounting:

```text
decode -> detect -> flow key -> flow update -> aggregate
```

## What is detected

Thresholds are constants in `crates/sentinel-detect`, not settings. A setting with no control to
change it is a promise the interface cannot keep.

| Detector | Fires when | Known false-positive source |
| --- | --- | --- |
| ARP deception | Two MACs answer for one IPv4 address after the conflict is sustained: the incumbent answers *after* the challenger appears, or the challenger wins three times while the incumbent is silent | A DHCP hand-off that lingers, or a virtualisation host answering for a guest |
| Port scan | One source contacts 20 distinct ports on one destination within 60 seconds | A monitoring agent or an application with many backends |
| Host sweep | One source contacts 20 distinct hosts on one port within 60 seconds | Service discovery, vulnerability scanners an operator runs on purpose |
| TCP flag anomaly | A header combination ordinary stacks do not produce (for example SYN and FIN together, or no flags at all) | Broken middleboxes and some embedded devices |
| Cleartext protocol | A connection to FTP, Telnet, SMTP, TFTP, POP3 or IMAP by port | A service on a non-standard port is missed; a plaintext service on a TLS port is missed |
| Possible beaconing | Eight or more successive connections to one destination with a mean interval between 5 seconds and 1 hour and jitter of at most 15% | Anything that polls: chat clients, mail, telemetry, update checks |
| Large outbound transfer | More than 10 MiB of payload leaves for one public destination inside 60 seconds with an inbound:outbound ratio worse than 1:20 | Backups, uploads of video, cloud sync |

Single-packet disagreement is never acted on. One ARP address change is indistinguishable from a
lease moving; a scan is a *set* of attempts, not one SYN.

## What is deliberately not inspected

Payload bytes are never retained, and therefore never inspected — not even to look for a pattern.
Every detector works from headers, timings and byte counts. This is why the cleartext detector is
port-based: inferring plaintext from payload shape would require keeping the payloads, which
would make Sentinel's central privacy promise false.

It is also why there is no DNS-tunnelling detector yet. That rule needs DNS query parsing, not
payload retention, and it is the next rule worth adding.

## Determinism and bounded state

- **Deterministic.** Time enters only as the packet's own timestamp. There is no wall clock, no
  timer and no random input, so replaying a capture file twice produces identical findings.
- **Bounded.** Every table has a ceiling and a documented behaviour at that ceiling. A spoofed
  source address is free; an attacker can send from a million addresses precisely to turn a
  detector into a memory-exhaustion bug. The engine also caps the retained finding list at 512
  and reports what it discarded rather than presenting a truncated list as complete.
- **Quiet by construction.** A finding is emitted on the packet that crosses a threshold, and is
  not re-emitted for every packet after it. Further observations update the same finding.
- **Escalate, never de-escalate.** A finding's severity and confidence can rise as more evidence
  arrives. They never fall, in memory or in the SQL upsert, so a quieter later observation cannot
  bury an earlier serious one.

## Storage and retention

A finding is stored as columns for the fields the interface sorts and filters on, plus JSON for
evidence and advice. Stored enumerations use stable string identifiers; a row whose identifier
this build cannot understand is reported as corruption rather than defaulted to "info", because
a silently-downgraded alert is worse than a visible error.

Findings follow the **flows** retention period. They are event records, not chart data: keeping a
finding after the flow that caused it has been deleted would leave an alert with no supporting
evidence.

## The response boundary

Detection does not act. `crates/sentinel-response` contains the separate, consent-gated path that
can construct a corrective ARP frame. It:

- requires a named authorisation (who and which network) before it will do anything
- writes an audit record before acting
- is exercised by its own tests, but is **not yet reachable from the application**: there is no
  injector implementation in `sentinel-capture` and no CLI flag that invokes it

That gap is stated here rather than implied away. The read-only guarantee in
[SECURITY.md](../SECURITY.md) remains true in practice because nothing in the shipped binaries
calls the response path.

## Testing

A detector is a pure function of packets in order, so its tests are a table: feed frames, assert
findings. No capture driver, no privileges, no network. Every detector has at least:

- a **positive** case that must fire
- a **negative** case that must not, because a detector with only positive tests fires on everything
- a **boundary** case at the threshold
- a **benign look-alike**, the case that decides whether the detector is usable

The integration tests in `crates/sentinel-core/tests/offline_pipeline.rs` replay generated PCAP
files through the real capture chain and assert the same findings a live session would produce.
`fixtures/detection-traffic.pcap` exists for that purpose at the CLI level: its own test asserts
that replaying it produces exactly one finding per behaviour, so a demonstration of the engine
cannot drift away from what the engine does.

## What Sentinel will not do

- **Block traffic automatically without consent.** The response path is opt-in, named and
  audited. There is no silent enforcement.
- **Send data anywhere.** See [SECURITY.md](../SECURITY.md).
- **Score without explaining.** A finding that cannot state its own reason is not finished.
- **Learn from your traffic in the background.** No silent model training. A future baseline must
  be computed, shown and resettable.
- **Claim a verdict from a single observation.** A finding is an observation worth attention, not
  a conclusion. The wording reflects that.
