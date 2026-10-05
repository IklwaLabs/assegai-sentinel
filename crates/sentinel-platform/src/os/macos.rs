//! macOS interface discovery and capability probing (libpcap over BPF).
//!
//! BSD names are the capture identifiers (`en0`, `en1`, `lo0`). Link state is not
//! exposed by libpcap on macOS, so `is_up` reflects device presence and the UI presents
//! it as such. Wireless detection is name-based inference and is labelled as such.

use sentinel_common::net::{InterfaceKind, NetworkInterface};

use crate::capabilities::{Capabilities, CaptureBackend, PrivilegeState};
use crate::error::Result;

/// macOS: libpcap over `/dev/bpf`.
pub(super) fn interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = super::base::pcap_devices()?;

    for iface in &mut interfaces {
        iface.kind = classify(iface);
        iface.is_loopback = iface.kind == InterfaceKind::Loopback;
        iface.is_virtual =
            iface.kind == InterfaceKind::Virtual || iface.kind == InterfaceKind::Tunnel;
        // libpcap on macOS does not report link state; a listed device is usable.
        iface.is_up = true;
        iface.capture_ready = true;
        iface.capture_blocked_reason = None;
    }

    interfaces.sort_by(|a, b| {
        a.is_loopback.cmp(&b.is_loopback).then_with(|| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        })
    });

    Ok(interfaces)
}

/// Classifies a macOS BSD interface name.
fn classify(iface: &NetworkInterface) -> InterfaceKind {
    let name = iface.id.to_ascii_lowercase();
    if name.starts_with("lo") {
        InterfaceKind::Loopback
    } else if name.starts_with("utun") || name.starts_with("ppp") || name.starts_with("ipsec") {
        InterfaceKind::Tunnel
    } else if name.starts_with("bridge") || name.starts_with("vmenet") || name.starts_with("awdl") {
        InterfaceKind::Virtual
    } else if name.starts_with("llw") || name.starts_with("ap") {
        InterfaceKind::Wireless
    } else {
        InterfaceKind::Ethernet
    }
}

/// macOS capabilities, including the BPF device permission path.
pub(super) fn capabilities() -> Result<Capabilities> {
    let present = super::base::library_present();
    let privilege = privilege_state();
    let mut notes = vec![
        "Capture uses libpcap over /dev/bpf.".to_string(),
        "macOS requires either `sudo sentinel capture` or access to /dev/bpf*: \
         `sudo chmod 640 /dev/bpf*` and membership in the access_bpf group (macOS 13+)."
            .to_string(),
    ];
    if !present {
        notes.push("libpcap was not detected. Install it with `brew install libpcap`.".to_string());
    }

    Ok(Capabilities {
        backend: CaptureBackend::Bpf,
        library_present: present,
        requires_elevation: true,
        privilege,
        loopback_supported: true,
        max_snaplen: super::base::max_snaplen(),
        notes,
    })
}

/// Effective user id of this process.
#[must_use]
pub(super) fn privilege_state() -> PrivilegeState {
    // SAFETY: geteuid takes no arguments, has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        PrivilegeState::Elevated
    } else {
        PrivilegeState::NotElevated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsd_names_are_classified() {
        let cases = [
            ("lo0", InterfaceKind::Loopback),
            ("utun5", InterfaceKind::Tunnel),
            ("bridge100", InterfaceKind::Virtual),
            ("llw0", InterfaceKind::Wireless),
            ("en0", InterfaceKind::Ethernet),
            ("en7", InterfaceKind::Ethernet),
        ];
        for (name, expected) in cases {
            let iface = NetworkInterface::new(name, name);
            assert_eq!(
                classify(&iface),
                expected,
                "unexpected classification for {name}"
            );
        }
    }
}
