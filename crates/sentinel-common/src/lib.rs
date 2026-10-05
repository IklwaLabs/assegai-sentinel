//! Foundational types shared by every Sentinel crate.
//!
//! This crate is the bottom of the dependency graph. It must not depend on any other
//! Sentinel crate, must not touch the operating system, and must stay cheap enough to
//! use from the packet hot path.
//!
//! Contents:
//! - [`clock`]: monotonic/unix time helpers and human-readable formatting.
//! - [`error`]: the [`error::UserFacing`] contract that turns typed errors into
//!   actionable messages.
//! - [`net`]: platform-neutral network types (MAC addresses, interfaces).
//! - [`packet`]: the normalized packet model produced by the parser.
//! - [`config`]: typed configuration schema with validation.
//! - [`metrics`]: engine counters surfaced in the UI and CLI.
//! - [`throttle`]: coalescing helper for UI updates.

pub mod clock;
pub mod config;
pub mod error;
pub mod metrics;
pub mod net;
pub mod packet;
pub mod throttle;

/// Crate-wide result alias for fallible Sentinel operations.
pub type Result<T, E> = std::result::Result<T, E>;
