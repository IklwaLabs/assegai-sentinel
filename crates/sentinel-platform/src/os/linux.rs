//! Linux interface discovery and capability probing (libpcap).
//!
//! The capture backend opens devices by name, so the interface `id` is the kernel name
//! (`eth0`, `wlan0`). Link state, hardware address, device type and wireless status come
//! from `/sys/class/net/<name>`, which is the authoritative source on Linux.

use std::path::{Path, PathBuf};

use sentinel_common::net::{InterfaceKind, NetworkInterface};

use crate::capabilities::{Capabilities, CaptureBackend, PrivilegeState};
use crate::error::Result;

const SYSFS_NET: &str = "/sys/class/net";

/// Linux: libpcap over AF_PACKET.
pub(super) fn interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = super::base::pcap_devices()?;

    for iface in &mut interfaces {
        enrich(iface);
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

/// Adds Linux-specific facts to an interface record.
fn enrich(iface: &mut NetworkInterface) {
    let base = PathBuf::from(SYSFS_NET).join(&iface.id);

    if let Some(index) = super::base::read_trimmed(&base.join("ifindex")) {
        iface.description = Some(match iface.description.clone() {
            Some(desc) if desc != iface.id => format!("{desc} (ifindex {index})"),
            _ => format!("ifindex {index}"),
        });
    }

    if let Some(mac) = super::base::read_trimmed(&base.join("address")) {
        iface.mac = sentinel_common::net::MacAddr::parse(&mac);
    }

    // ARPHRD type: 1 = Ethernet, 772 = loopback, 512 = PPP, 801 = Wi-Fi-ish tunnels.
    if let Some(device_type) = super::base::read_trimmed(&base.join("type")) {
        iface.kind = match device_type.as_str() {
            "772" => InterfaceKind::Loopback,
            "1" => InterfaceKind::Ethernet,
            "512" => InterfaceKind::Tunnel,
            _ => iface.kind,
        };
    }

    if base.join("wireless").is_dir()
        || Path::new("/proc/net/wireless").exists() && is_wireless(&base)
    {
        iface.kind = InterfaceKind::Wireless;
    }

    if let Some(state) = super::base::read_trimmed(&base.join("operstate")) {
        // "unknown" is reported by devices whose state cannot be determined (for example
        // some Wi-Fi adapters); treating it as up avoids hiding a usable adapter.
        match state.as_str() {
            "up" => iface.is_up = true,
            "down" | "lowerlayerdown" => iface.is_up = false,
            _ => {}
        }
    }

    iface.is_loopback = iface.kind == InterfaceKind::Loopback;
    iface.is_virtual = iface.kind == InterfaceKind::Virtual || iface.kind == InterfaceKind::Tunnel;

    if !iface.is_up {
        iface.capture_ready = false;
        iface.capture_blocked_reason =
            Some("This interface is administratively down. Bring it up and try again.".to_string());
    }
    if iface.mac.is_none_or(sentinel_common::net::MacAddr::is_zero) && !iface.is_loopback {
        iface.description = iface
            .description
            .clone()
            .or_else(|| Some("no hardware address".into()));
    }
}

/// True when the sysfs entry looks like a wireless device.
fn is_wireless(base: &Path) -> bool {
    base.join("phy80211").is_dir() || base.join("wireless").is_dir()
}

/// Linux capabilities, including the privilege path that works here.
pub(super) fn capabilities() -> Result<Capabilities> {
    let present = super::base::library_present();
    let privilege = privilege_state();
    let mut notes = vec![
        "Capture uses libpcap over AF_PACKET sockets.".to_string(),
        "Unprivileged capture: grant the binary packet capabilities once with \
         `sudo setcap cap_net_raw,cap_net_admin=eip <path-to-sentinel>`."
            .to_string(),
        "Alternatively add your user to the `pcap` group.".to_string(),
    ];
    if present && privilege == PrivilegeState::Elevated {
        notes.push("Running as root: no capability grant is required.".to_string());
    }
    if !present {
        notes.push("libpcap was not detected. Install it with your package manager.".to_string());
    }

    Ok(Capabilities {
        backend: CaptureBackend::Libpcap,
        library_present: present,
        requires_elevation: true,
        privilege,
        loopback_supported: true,
        max_snaplen: super::base::max_snaplen(),
        notes,
    })
}

/// Effective user id of this process, used to detect root.
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
    fn enrichment_reads_sysfs_when_present() {
        if !Path::new(SYSFS_NET).is_dir() {
            return; // Not Linux; nothing to assert.
        }
        let mut iface = NetworkInterface::new("lo", "lo");
        iface.kind = InterfaceKind::Other;
        enrich(&mut iface);
        assert_eq!(iface.kind, InterfaceKind::Loopback);
        assert!(iface.is_loopback);
    }
}
