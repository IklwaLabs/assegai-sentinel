# Security Policy

## What Sentinel does with your data

Sentinel is local-first. This is not a policy aspiration; it is a property of the code, and it
is worth stating precisely so you can check it rather than take it on trust.

**Sentinel never opens an outbound network connection.** There is no HTTP client, no DNS
resolver, no telemetry endpoint and no update check anywhere in the workspace. The only sockets
it opens are the ones the capture driver creates to read frames from an adapter. You can verify
this:

```bash
# No networking crates in the dependency graph of the engine or the apps.
cargo tree -p sentinel-core | grep -Ei "reqwest|hyper|curl|native-tls|rustls|tokio-tungstenite"
# Expects no output.

# No code path constructs an outbound address.
grep -rn "TcpStream\|UdpSocket\|connect(" crates/ apps/ --include=*.rs
# Expects no matches outside of tests and the capture driver bindings.
```

**Sentinel stores what it observes, locally, in one SQLite file** under your user data
directory. Nothing is written anywhere else except log files, in the same directory tree.

**Sentinel does not retain packet payloads.** It decodes frames into headers, flows and
aggregate counters. The payload bytes of a packet are not stored, and the database schema has no
column for them. Detection works only from headers, timings and byte counts; it never reads
packet contents, not even to look for a pattern.

An earlier build shipped a `capturePayloadSamples` setting that no code ever read. It was
removed in v0.2: packets were already never stored, so there was nothing for it to control, and a
setting that promises behaviour no code performs is worse than no setting. See
[docs/MATURITY-ANALYSIS.md](docs/MATURITY-ANALYSIS.md).

## Sentinel and your network: read by default, respond only with your consent

**Sentinel does not modify your network unless you explicitly turn active response on.** Out of
the box it only reads.

Two separate facts, both true in this build:

1. **The shipped binaries contain no packet-injection path.** There is no injector in
   `sentinel-capture`, no send API exposed to the engine, and no command that invokes one.
   Today Sentinel cannot change your network, even if every response setting were enabled.
2. **The response machinery exists and is tested, but is not reachable.** `sentinel-response`
   holds the consent gate, the sustained-conflict state machine and the corrective-frame
   constructor that a future injector would use. Nothing in the application calls it yet.

The read-only guarantee used to be unconditional, and it was worth something. It is now
conditional *in design*, because that machinery exists; the conditions are enforced inside
`sentinel-response` and are designed to be hard to satisfy by accident:

1. **Off by default.** Every existing installation upgrades into "read only". Turning response
   on is never a side effect of an upgrade, a config migration or a new default.
2. **Requires a named authorisation.** To enable it you must enter who is authorising Sentinel
   to act and which network it is acting on. Sentinel cannot verify that you own a network,
   and does not pretend to — it records your statement. An incomplete authorisation is refused
   when it is created, so one can never be saved and discovered as a surprise mid-incident.
3. **Every action is audited.** Each attempt is written to a durable record — what was done,
   to which address, on whose authority — *before* it is attempted, with the outcome recorded
   afterwards. A failed attempt is recorded as a failure and never as a change.
4. **Only sustained conflicts are acted on.** A single disagreement between two MAC addresses
   for one IP is almost always a DHCP re-address, and Sentinel will not react to one. It acts
   when two machines are both answering for the same address, or when a new claimant takes an
   address and holds it.

**What response will be able to do once it is reachable.** One thing: send a *gratuitous ARP
reply* that re-asserts an address to its true owner, repairing hosts on your segment whose caches
were poisoned. It does not modify DNS, does not block or shape traffic, and does not transmit
anything that is not a direct correction of a specific, detected fault.

**What response deliberately does not do.** It does not deauthenticate anyone, does not touch
802.11 management frames, and does not attempt to evict or interfere with access points.

### Why the WiFi limit is a limit, not an oversight

Sentinel **cannot see 802.11 management frames** — no beacons, no probe responses, no
deassociation or deauthentication frames. The WiFi driver strips the 802.11 header before
frames reach a packet socket, and management frames are not delivered to it at all. Detecting
an evil twin, a rogue access point or a deauthentication flood would therefore need a
fundamentally different capture mechanism — monitor mode on Linux, or each operating system's
native WiFi scanning API, with privileges Sentinel does not request.

Sentinel therefore cannot tell you that the WiFi you joined is not the WiFi it claims to be.
It can tell you that, once connected, something on the network is answering for an address
that is not its own.

This is also why response does not attempt to deauthenticate an attacker. Beyond the
technical impossibility, doing so would require injecting management frames Sentinel cannot
even observe.

### A legal note, stated plainly

Injecting traffic onto a network you do not own or have written permission to test is a
criminal offence in many jurisdictions, including under Tanzania's Cybercrimes Act, **even
when the traffic is corrective**. Sentinel asks for a named authorisation for that reason and
not as a formality. If you are not certain you are authorised, leave response off — detection
is unaffected and costs you nothing.

## What Sentinel needs, and why

| Requirement | Reason |
| --- | --- |
| Elevated privileges | Reading frames from a network adapter is privileged on every platform Sentinel supports. Windows requires an administrator token for Npcap; Linux requires `CAP_NET_RAW` or root; macOS requires membership in `access_bpcap`. |
| A capture driver | Npcap on Windows, libpcap on Linux. The driver is what actually reads the wire. |
| A writable data directory | The SQLite database, logs and exports live there. |

Sentinel requests no other permission. It has no network, filesystem-beyond-its-own-directory,
camera, microphone or input access. The Tauri window runs with a Content Security Policy that
allows scripts and styles from the bundle only, and does not permit remote code.

## Reporting a vulnerability

If you find a security problem in Sentinel, report it privately rather than opening a public
issue. Include:

- what you found, and what an attacker could achieve
- the version or commit
- how to reproduce it
- your platform and Sentinel's reported capabilities (`sentinel doctor` output)

Report to **security@iklwalabs.com**. Include the same detail. You should receive an
acknowledgement within a few business days.

## What to do while waiting

Do not disclose details publicly until a fix or mitigation is available. If the issue involves
data leaving your machine, treat the machine as potentially compromised and disconnect it.

## Scope

In scope: any Sentinel code, in any crate under `crates/`, `apps/` or `tools/`.

Out of scope: vulnerabilities in the operating system, in Npcap or libpcap, or in Tauri and its
webview, that Sentinel does not introduce or worsen. Report those to their own maintainers; if
Sentinel's use of them is the problem, that *is* in scope and we want to hear about it.

Deliberately out of scope: Sentinel is a monitoring tool, and running it against a network you
do not administer is your responsibility, not a vulnerability in the software.