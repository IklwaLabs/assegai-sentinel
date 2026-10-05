# Assegai Sentinel

Local-first network visibility and threat detection.

See [README.md](README.md) for what it does and how to build it.

## Documentation

| Document | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate map, concurrency, storage, design decisions |
| [ROADMAP.md](ROADMAP.md) | What is built, what is next |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Prerequisites, running, testing, conventions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | What a contribution should look like |
| [SECURITY.md](SECURITY.md) | What Sentinel does with your data, and how to report a vulnerability |
| [docs/PACKET_PIPELINE.md](docs/PACKET_PIPELINE.md) | How a frame becomes a connection, and where data can be lost |
| [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | The detection design, and why it is not implemented yet |
| [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) | Per-platform drivers, privileges and limitations |

## Quick start

```bash
cargo run -p sentinel-cli -- doctor      # can this machine capture?
cargo run -p sentinel-cli -- interfaces
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap
```

## Licence

Apache-2.0. Built by IklwaLabs.