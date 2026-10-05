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
column for them. A setting exists to retain small payload samples as evidence for future threat
rules; it is off by default, and enabling it changes what is written to your own disk, not what
leaves it.

**Sentinel does not modify your network.** It reads. There is no packet injection, no ARP
spoofing, no DNS manipulation and no traffic shaping anywhere in the codebase.

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