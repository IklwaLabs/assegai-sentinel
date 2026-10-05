//! Fallback for operating systems without a capture backend.
//!
//! Sentinel targets Windows, Linux, macOS and Android. This module exists so that an
//! unsupported target gets an explicit, honest answer instead of a confusing empty list.

use sentinel_common::net::NetworkInterface;

use crate::capabilities::{Capabilities, CaptureBackend, PrivilegeState};
use crate::error::{PlatformError, Result};

/// No capture backend is compiled in for this target.
pub(super) fn interfaces() -> Result<Vec<NetworkInterface>> {
    Err(PlatformError::Unsupported {
        feature: "packet capture",
        platform: super::platform_name(),
    })
}

/// Reports the absence of a capture backend without failing the diagnostic path.
pub(super) fn capabilities() -> Result<Capabilities> {
    Ok(Capabilities {
        backend: CaptureBackend::Unsupported,
        library_present: false,
        requires_elevation: false,
        privilege: PrivilegeState::Unknown,
        loopback_supported: false,
        max_snaplen: 0,
        notes: vec![format!(
            "Iklwa Sentinel does not provide a capture backend for {} yet. \
             Supported targets: Windows, Linux, macOS, Android.",
            super::platform_name()
        )],
    })
}

/// Privilege state is unknown on an unsupported target.
#[must_use]
pub(super) fn privilege_state() -> PrivilegeState {
    PrivilegeState::Unknown
}
