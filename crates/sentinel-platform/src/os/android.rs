//! Android capture contract.
//!
//! On Android, packet capture is owned by the system: an app that wants to observe
//! traffic runs a `VpnService`, which hands the app a file descriptor for a TUN device.
//! Sentinel's job is therefore to consume that stream, not to enumerate NICs.
//!
//! The intended production path is:
//!
//! ```text
//! VpnService (Kotlin) -> TUN fd -> JNI/FFI bridge -> RawPacket -> sentinel-parser
//! ```
//!
//! This build contains no Android host application, so the honest answer is reported
//! rather than a fabricated interface list or a fake capture backend. When the Android
//! host lands, only this module changes: it exposes a capture adapter that reads the TUN
//! descriptor and publishes `RawPacket`s into the same bounded queue the desktop uses.
//! The decoder, flow engine, storage and detection code are shared unchanged.

use sentinel_common::net::NetworkInterface;

use crate::capabilities::{Capabilities, CaptureBackend, PrivilegeState};
use crate::error::{PlatformError, Result};

/// Android has no meaningful interface list for packet capture.
pub(super) fn interfaces() -> Result<Vec<NetworkInterface>> {
    Err(PlatformError::Unsupported {
        feature: "network interface enumeration",
        platform: "Android",
    })
}

/// Android capabilities: the tunnel backend exists, the host bridge does not yet.
pub(super) fn capabilities() -> Result<Capabilities> {
    Ok(Capabilities {
        backend: CaptureBackend::AndroidTun,
        library_present: false,
        requires_elevation: false,
        privilege: PrivilegeState::Unknown,
        loopback_supported: false,
        max_snaplen: 65_535,
        notes: vec![
            "Android captures traffic through the app's VpnService tunnel, not through \
             Wi-Fi or Ethernet adapters."
                .to_string(),
            "This build ships the shared Rust analysis core only. The Android host app \
             (VPN service + Kotlin bridge) is delivered in the Android milestone."
                .to_string(),
        ],
    })
}

/// Android does not expose an elevation concept.
#[must_use]
pub(super) fn privilege_state() -> PrivilegeState {
    PrivilegeState::Unknown
}
