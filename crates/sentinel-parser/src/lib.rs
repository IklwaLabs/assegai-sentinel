//! Packet decoding for Iklwa Sentinel.
//!
//! This crate owns three things:
//!
//! 1. [`PacketDecoder`]: a stateless, bounds-checked L2-L4 decoder producing
//!    [`sentinel_common::packet::NormalizedPacket`].
//! 2. [`pcap`]: a dependency-free classic PCAP file reader and writer, used for offline
//!    investigation, exports and golden test fixtures.
//! 3. [`fixtures`]: deterministic frame builders shared by unit tests, integration tests
//!    and future fixture tooling, so "what a DNS query looks like" has one definition.
//!
//! Everything here is a pure function of its input. That is what allows live capture and
//! offline analysis to share one code path instead of duplicating analysis logic.

pub mod decode;
pub mod fixtures;
pub mod pcap;

pub use decode::{DecodeError, PacketDecoder};
pub use pcap::{PcapFileError, PcapReader, PcapWriter};

// Re-exported so consumers depend only on the parser.
pub use sentinel_common::packet::NormalizedPacket;

#[cfg(test)]
mod decode_tests;
