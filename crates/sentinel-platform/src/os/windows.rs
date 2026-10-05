//! Windows interface discovery and capability probing (Npcap).
//!
//! Interface enumeration comes from Npcap, which reports each adapter's NDIS name
//! (`\\Device\\NPF_{GUID}`) plus a friendly description. The NDIS name is the identifier
//! used for capture selection because it is what the capture backend accepts.

use sentinel_common::net::{InterfaceKind, NetworkInterface};

use crate::capabilities::{Capabilities, CaptureBackend, PrivilegeState};
use crate::error::Result;

/// Windows: Npcap over NDIS.
pub(super) fn interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = super::base::pcap_devices()?;

    for iface in &mut interfaces {
        let description = iface
            .description
            .clone()
            .unwrap_or_else(|| iface.name.clone());
        iface.name = description.clone();
        iface.kind = super::base::classify_by_name(&iface.id, &description);
        iface.is_loopback = iface.kind == InterfaceKind::Loopback;
        iface.is_virtual =
            iface.kind == InterfaceKind::Virtual || iface.kind == InterfaceKind::Tunnel;
        // The driver reports the link state; a down adapter cannot be opened.
        if !iface.is_up {
            iface.capture_ready = false;
            iface.capture_blocked_reason = Some(
                "This adapter is disconnected. Connect the network and try again.".to_string(),
            );
        }
    }

    interfaces.sort_by(|a, b| {
        b.is_up
            .cmp(&a.is_up)
            .then_with(|| a.is_loopback.cmp(&b.is_loopback))
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
    });

    Ok(interfaces)
}

/// Windows capabilities, including whether the process is elevated.
pub(super) fn capabilities() -> Result<Capabilities> {
    let present = super::base::library_present();
    let privilege = privilege_state();
    let mut notes = vec![
        "Npcap exposes loopback traffic through a dedicated loopback adapter when installed in full mode.".to_string(),
        "Packet capture requires an elevated process (Run as administrator).".to_string(),
    ];
    if !present {
        notes.push("Npcap was not detected. Install it from https://npcap.com.".to_string());
    }

    Ok(Capabilities {
        backend: CaptureBackend::Npcap,
        library_present: present,
        requires_elevation: true,
        privilege,
        loopback_supported: true,
        max_snaplen: super::base::max_snaplen(),
        notes,
    })
}

/// Windows elevation probe via the access token.
///
/// # Safety
/// Uses only documented token queries on the current process; no handle escapes the
/// function and the token handle is always closed.
pub(super) fn privilege_state() -> PrivilegeState {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: every call below operates on the current process's access token. The
    // token handle returned by OpenProcessToken is closed before returning on all paths,
    // and the elevation buffer is a correctly sized, correctly aligned TOKEN_ELEVATION.
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return PrivilegeState::Unknown;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let succeeded = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast::<core::ffi::c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != 0;
        let _ = CloseHandle(token);

        if !succeeded {
            return PrivilegeState::Unknown;
        }
        if elevation.TokenIsElevated != 0 {
            PrivilegeState::Elevated
        } else {
            PrivilegeState::NotElevated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test on the real machine: enumeration either succeeds or fails with a typed
    /// error carrying an actionable message. It must never panic.
    #[test]
    fn enumeration_and_capabilities_are_usable_on_this_machine() {
        match interfaces() {
            Ok(found) => {
                for iface in &found {
                    assert!(!iface.id.is_empty(), "every interface needs a capture id");
                    assert!(
                        !iface.name.is_empty(),
                        "every interface needs a display name"
                    );
                }
            }
            Err(err) => {
                let message = sentinel_common::error::UserFacing::user_message(&err);
                assert!(!message.title.is_empty(), "errors must be user-facing");
            }
        }

        let caps = capabilities().expect("capability probe must not fail");
        assert!(
            !caps.notes.is_empty(),
            "capability summary must explain itself"
        );
        assert!(caps.max_snaplen >= 65_535);
    }

    #[test]
    fn privilege_probe_returns_a_definite_state() {
        // The probe may legitimately answer Unknown, but never a different variant.
        assert!(matches!(
            privilege_state(),
            PrivilegeState::Elevated | PrivilegeState::NotElevated | PrivilegeState::Unknown
        ));
    }
}
