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

## The download page is generated too

[`site/index.html`](../site/index.html) is the page served on the IklwaLabs website. It comes
from [`site/release-manifest.json`](../site/release-manifest.json) via
[`tools/generate-download-site.py`](../tools/generate-download-site.py), for the same reason: a
download page that offers a file the pipeline does not produce is a support ticket waiting to
happen.

The generator does not trust the manifest. It reads the version from `Cargo.toml`, the product
name from `tauri.conf.json` and the command list from the CLI's own enum, and refuses to write a
page that disagrees with any of them. It also checks that every in-page link resolves to a real
anchor.

```bash
python tools/generate-download-site.py           # write site/index.html
python tools/generate-download-site.py --check   # fail if stale
```

While no release is published, the page renders its buttons disabled with the filenames they
will use, and says why. It never renders a link to a file that does not exist.

## Quick start

```bash
cargo run -p sentinel-cli -- doctor      # can this machine capture?
cargo run -p sentinel-cli -- interfaces
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap
```

## Licence

Apache-2.0. Built by IklwaLabs.