//! Shared, portable baseline for interface discovery.
//!
//! The `pcap` device list is the portable baseline because it enumerates exactly the
//! devices the capture backend can actually open. Showing the user a device list that
//! pcap cannot open is a lie, so the OS modules only *enrich* this list, never replace it.

use std::net::IpAddr;

use sentinel_common::net::{InterfaceAddress, InterfaceKind, NetworkInterface};

use crate::error::{PlatformError, Result};

/// Lists devices as reported by the capture library.
pub(super) fn pcap_devices() -> Result<Vec<NetworkInterface>> {
    let devices = pcap::Device::list().map_err(|err| PlatformError::LibraryUnavailable {
        library: library_name(),
        details: err.to_string(),
    })?;

    Ok(devices.into_iter().map(device_to_interface).collect())
}

/// Name of the capture library on this platform, for error messages.
pub(super) const fn library_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "Npcap"
    } else {
        "libpcap"
    }
}

/// Whether the capture library loaded at all.
pub(super) fn library_present() -> bool {
    pcap::Device::list().is_ok()
}

/// Maximum snapshot length the backend accepts.
pub(super) fn max_snaplen() -> u32 {
    // 262144 is the practical ceiling across Npcap, Linux AF_PACKET and BPF. Anything
    // larger is rejected by the driver, so Sentinel caps here instead of failing later.
    262_144
}

/// Converts a capture-library device into a normalized interface.
fn device_to_interface(device: pcap::Device) -> NetworkInterface {
    let addresses = device
        .addresses
        .iter()
        .map(|addr| InterfaceAddress::new(addr.addr, prefix_len(addr.addr, addr.netmask)))
        .collect::<Vec<_>>();

    let mut kind = classify_by_name(&device.name, device.desc.as_deref().unwrap_or(&device.name));
    if device.flags.is_wireless() {
        kind = InterfaceKind::Wireless;
    }
    if device.flags.is_loopback() {
        kind = InterfaceKind::Loopback;
    }

    let is_loopback = kind == InterfaceKind::Loopback;
    let is_up = device.flags.is_up();

    NetworkInterface {
        name: device.desc.clone().unwrap_or_else(|| device.name.clone()),
        description: device.desc,
        addresses,
        mac: None,
        kind,
        is_up,
        is_loopback,
        is_virtual: kind == InterfaceKind::Virtual || kind == InterfaceKind::Tunnel,
        capture_ready: is_up,
        capture_blocked_reason: None,
        id: device.name,
    }
}

/// Derives a prefix length from an address/netmask pair.
fn prefix_len(addr: IpAddr, netmask: Option<IpAddr>) -> u8 {
    match (addr, netmask) {
        (IpAddr::V4(_), Some(IpAddr::V4(mask))) => {
            u32::from_be_bytes(mask.octets()).count_ones() as u8
        }
        (IpAddr::V6(_), Some(IpAddr::V6(mask))) => {
            u128::from_be_bytes(mask.octets()).count_ones() as u8
        }
        // IPv6 point-to-point links report a host mask; a /64 is the useful assumption.
        (IpAddr::V6(_), None) => 64,
        (IpAddr::V4(_), None) => 24,
        _ => 0,
    }
}

/// Classifies an interface from its identifiers.
///
/// This is inference, not truth: names are the only portable signal available before
/// enrichment, so the OS modules refine it and the UI never presents it as certain.
pub(super) fn classify_by_name(raw_name: &str, display_name: &str) -> InterfaceKind {
    let haystack = format!("{raw_name} {display_name}").to_ascii_lowercase();

    if matches!(raw_name, "lo" | "lo0" | "Loopback Pseudo-Interface 1")
        || haystack.contains("loopback")
        || haystack.contains("pseudo")
    {
        return InterfaceKind::Loopback;
    }
    if ["utun", "tun", "tap", "wg", "ppp", "ipsec", "vpn"]
        .iter()
        .any(|p| haystack.contains(p))
    {
        return InterfaceKind::Tunnel;
    }
    if [
        "vethernet",
        "vmware",
        "virtualbox",
        "hyper-v",
        "docker",
        "veth",
        "virbr",
        "bridge",
    ]
    .iter()
    .any(|p| haystack.contains(p))
    {
        return InterfaceKind::Virtual;
    }
    if ["wi-fi", "wifi", "wlan", "wireless", "airport", "llw", "wlp"]
        .iter()
        .any(|p| haystack.contains(p))
    {
        return InterfaceKind::Wireless;
    }
    if [
        "ethernet", "eth", "en", "en0", "igb", "igc", "e1000", "rtl", "bnxt",
    ]
    .iter()
    .any(|p| haystack.contains(p))
    {
        return InterfaceKind::Ethernet;
    }
    InterfaceKind::Other
}

/// Reads a single line from a sysfs or procfs file, trimming whitespace.
///
/// Used by the Linux enrichment layer to read link state, index and type from `/sys/class/net`.
/// A missing or unreadable file is not an error: enrichment is best-effort, because the
/// capture-library list is already authoritative for what can be opened.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only Linux reads sysfs")
)]
pub(super) fn read_trimmed(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_length_from_ipv4_mask() {
        assert_eq!(
            prefix_len(
                "192.168.1.10".parse().expect("v4"),
                Some("255.255.255.0".parse().expect("mask"))
            ),
            24
        );
        assert_eq!(
            prefix_len(
                "10.0.0.1".parse().expect("v4"),
                Some("255.0.0.0".parse().expect("mask"))
            ),
            8
        );
        assert_eq!(
            prefix_len(
                "10.0.0.1".parse().expect("v4"),
                Some("255.255.255.255".parse().expect("mask"))
            ),
            32
        );
    }

    #[test]
    fn prefix_length_from_ipv6_mask() {
        assert_eq!(
            prefix_len(
                "2606:4700::1".parse().expect("v6"),
                Some("ffff:ffff:ffff::".parse().expect("mask"))
            ),
            48
        );
        assert_eq!(prefix_len("fe80::1".parse().expect("v6"), None), 64);
    }

    #[test]
    fn classification_covers_common_devices() {
        assert_eq!(classify_by_name("lo", "lo"), InterfaceKind::Loopback);
        assert_eq!(
            classify_by_name("\\Device\\NPF_1", "Npcap Loopback Adapter"),
            InterfaceKind::Loopback
        );
        assert_eq!(classify_by_name("utun4", "utun4"), InterfaceKind::Tunnel);
        assert_eq!(
            classify_by_name("veth1234", "veth1234"),
            InterfaceKind::Virtual
        );
        assert_eq!(classify_by_name("wlan0", "wlan0"), InterfaceKind::Wireless);
        assert_eq!(classify_by_name("Wi-Fi", "Wi-Fi"), InterfaceKind::Wireless);
        assert_eq!(classify_by_name("eth0", "eth0"), InterfaceKind::Ethernet);
        assert_eq!(classify_by_name("zz9", "zz9"), InterfaceKind::Other);
    }

    #[test]
    fn mac_parsing_lives_on_the_shared_type() {
        // Parsing is a property of the address, not of any one OS layer, so it is tested in
        // sentinel-common. This layer only forwards to it, which is asserted here.
        use sentinel_common::net::MacAddr;
        assert_eq!(
            MacAddr::parse("1a:2b:3c:4d:5e:6f\n"),
            Some(MacAddr::from_bytes([0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f]))
        );
        assert_eq!(MacAddr::parse("1a:2b:3c"), None);
    }
}
