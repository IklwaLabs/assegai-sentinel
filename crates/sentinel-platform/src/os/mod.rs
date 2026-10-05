//! Per-operating-system interface discovery and capability probing.
//!
//! Every operating system module implements the same three functions and nothing else.
//! Business logic never branches on `cfg(target_os)`; it consumes the normalized result.

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod imp;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod imp;

#[cfg(target_os = "android")]
#[path = "android.rs"]
mod imp;

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "android"
)))]
#[path = "unsupported.rs"]
mod imp;

#[cfg(not(target_os = "android"))]
#[path = "base.rs"]
pub(super) mod base;

use sentinel_common::net::NetworkInterface;

use crate::capabilities::{Capabilities, PrivilegeState};
use crate::error::Result;

/// Name of the running operating system, for diagnostics output.
#[must_use]
pub const fn platform_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "android") {
        "Android"
    } else {
        "unsupported"
    }
}

/// Enumerates network interfaces, enriched with per-OS metadata.
///
/// # Errors
/// Returns [`crate::error::PlatformError`] when the OS interface list is unavailable.
pub fn interfaces() -> Result<Vec<NetworkInterface>> {
    imp::interfaces()
}

/// Probes what capture is possible in this process right now.
///
/// # Errors
/// Returns [`crate::error::PlatformError`] when the capture library cannot be probed.
pub fn capabilities() -> Result<Capabilities> {
    imp::capabilities()
}

/// Determines whether this process is elevated.
#[must_use]
pub fn privilege_state() -> PrivilegeState {
    imp::privilege_state()
}
