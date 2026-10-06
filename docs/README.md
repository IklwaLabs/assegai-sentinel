# Assegai Sentinel

Local-first network visibility and threat detection.

See [README.md](../README.md) for what it does and how to build it.

## Start here

**[`Sentinel-Reference.pdf`](Sentinel-Reference.pdf)** is the whole product in one document:
architecture, how to run it, how to control it, and what to do when something is wrong. If you
read one thing, read that.

## Documentation

| Document | What it covers |
| --- | --- |
| [**Sentinel-Reference.pdf**](Sentinel-Reference.pdf) | Everything, in one place. The product reference. |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Crate map, concurrency, storage, design decisions |
| [ROADMAP.md](../ROADMAP.md) | What is built, what is next |
| [DEVELOPMENT.md](../DEVELOPMENT.md) | Prerequisites, running, testing, conventions |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | What a contribution should look like |
| [SECURITY.md](../SECURITY.md) | What Sentinel does with your data, and how to report a vulnerability |
| [PACKET_PIPELINE.md](PACKET_PIPELINE.md) | How a frame becomes a connection, and where data can be lost |
| [DETECTION_ENGINE.md](DETECTION_ENGINE.md) | The detection design, and why it is not implemented yet |
| [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) | Per-platform drivers, privileges and limitations |

## The product reference is generated

`Sentinel-Reference.pdf` is built from this repository by
[`tools/generate-reference-pdf.py`](../tools/generate-reference-pdf.py), which reads the facts out
of the code itself: configuration fields from the structs, commands from the enums, table names
from the migrations, test counts by running the suite.

That is the point. A document nobody regenerates goes stale silently, and a stale architecture
document is worse than none — so a field that no longer exists stops appearing, and a command
that was added shows up by itself.

```bash
pip install reportlab
python tools/generate-reference-pdf.py
```

The PDF is committed alongside its generator so a reader who clones the repository has the
document without needing Python.

## Quick start

```bash
cargo run -p sentinel-cli -- doctor      # can this machine capture?
cargo run -p sentinel-cli -- interfaces
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap
```

## Licence

Apache-2.0. Built by IklwaLabs.