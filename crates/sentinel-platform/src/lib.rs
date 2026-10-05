//! Operating system integration for Sentinel.
//!
//! This crate is the **only** place allowed to contain `cfg(target_os)` branches and
//! direct OS API calls. Everything above it consumes [`NetworkInterface`] and
//! [`Capabilities`] and never asks what operating system it is running on.
//!
//! Structure:
//! - [`error`]: typed platform errors with per-OS user-facing messages.
//! - [`os`]: per-OS interface discovery and capability probing (`windows`, `linux`,
//!   `macos`, `android`, plus an explicit fallback for unsupported targets).
//! - [`capabilities`]: what capture is possible in this process right now.
//! - [`paths`]: per-OS application data, configuration, log and export locations.
//! - [`settings`]: configuration file load/save built on [`paths`].

pub mod capabilities;
pub mod error;
pub mod os;
pub mod paths;
pub mod settings;

pub use capabilities::{Capabilities, CaptureBackend, PrivilegeState};
pub use error::{PlatformError, Result};
pub use os::{capabilities, interfaces, privilege_state};
pub use paths::AppPaths;
