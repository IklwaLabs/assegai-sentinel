//! Platform-neutral network types.
//!
//! These types are the contract between `sentinel-platform` (which knows about
//! operating systems) and everything above it (which must not).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A 48-bit Ethernet hardware address.
///
/// Serializes as the canonical `aa:bb:cc:dd:ee:ff` string rather than a byte array, so
/// the API contract stays readable and stable for the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl Default for MacAddr {
    /// The all-zero address, matching [`MacAddr::ZERO`]. An unknown hardware address is
    /// represented as zero rather than as a missing value, because "seen on the wire but
    /// unidentified" is common and is not the same as "no link layer".
    fn default() -> Self {
        MacAddr::ZERO
    }
}

impl MacAddr {
    /// The all-zero address, used when a device is not yet known.
    pub const ZERO: MacAddr = MacAddr([0; 6]);
    /// The broadcast address.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// Wraps six raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 6] {
        self.0
    }

    /// Parses the canonical `aa:bb:cc:dd:ee:ff` form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut bytes = [0u8; 6];
        let mut count = 0usize;
        for part in text.trim().split(':') {
            let value = u8::from_str_radix(part, 16).ok()?;
            if count >= 6 {
                return None;
            }
            bytes[count] = value;
            count += 1;
        }
        (count == 6).then_some(MacAddr(bytes))
    }

    /// True when every byte is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        let [a, b, c, d, e, f] = self.0;
        (a | b | c | d | e | f) == 0
    }

    /// True for the Ethernet broadcast address.
    #[must_use]
    pub const fn is_broadcast(self) -> bool {
        let [a, b, c, d, e, f] = self.0;
        (a & b & c & d & e & f) == 0xff
    }

    /// True when the group bit of the first octet is set (IPv4 multicast mapping).
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0x01 == 0x01
    }

    /// Returns the vendor-assigned OUI prefix used for vendor lookups.
    #[must_use]
    pub const fn oui(self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        MacAddr(value)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl serde::Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        MacAddr::parse(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid MAC address: {text}")))
    }
}

/// A single address configured on an interface.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceAddress {
    /// The IP address itself.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix_len: u8,
}

impl InterfaceAddress {
    /// Creates an address entry.
    #[must_use]
    pub const fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }

    /// True for IPv6 link-local (`fe80::/10`) addresses.
    #[must_use]
    pub fn is_link_local(&self) -> bool {
        match self.addr {
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
            IpAddr::V4(_) => false,
        }
    }
}

/// What kind of hardware or virtual device an interface represents.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    /// Loopback pseudo-device.
    Loopback,
    /// Wired Ethernet.
    Ethernet,
    /// Wi-Fi.
    Wireless,
    /// VPN or other tunnel device.
    Tunnel,
    /// Container bridge, hypervisor adapter or other software device.
    Virtual,
    /// Anything not classified.
    #[default]
    Other,
}

impl InterfaceKind {
    /// Lowercase label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            InterfaceKind::Loopback => "Loopback",
            InterfaceKind::Ethernet => "Ethernet",
            InterfaceKind::Wireless => "Wireless",
            InterfaceKind::Tunnel => "Tunnel",
            InterfaceKind::Virtual => "Virtual",
            InterfaceKind::Other => "Other",
        }
    }
}

/// A network interface as presented to the user.
///
/// `id` is the stable platform identifier (Windows interface index, Linux
/// `ifindex`, macOS BSD name) and is what capture selection is keyed on. `name` is the
/// label shown in the interface picker.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    /// Stable platform identifier.
    pub id: String,
    /// Display name, e.g. `Ethernet` or `en0`.
    pub name: String,
    /// Longer description when the OS provides one.
    #[serde(default)]
    pub description: Option<String>,
    /// Configured addresses.
    #[serde(default)]
    pub addresses: Vec<InterfaceAddress>,
    /// Hardware address, when the device has one.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// Device classification.
    pub kind: InterfaceKind,
    /// Whether the OS reports the link as administratively up.
    pub is_up: bool,
    /// Whether the device is a loopback pseudo-interface.
    pub is_loopback: bool,
    /// Whether the device is software-emulated.
    pub is_virtual: bool,
    /// Whether Sentinel can open this interface for capture in the current context.
    pub capture_ready: bool,
    /// Why capture is unavailable, in plain language, when `capture_ready` is false.
    #[serde(default)]
    pub capture_blocked_reason: Option<String>,
}

impl Default for NetworkInterface {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            description: None,
            addresses: Vec::new(),
            mac: None,
            kind: InterfaceKind::Other,
            is_up: true,
            is_loopback: false,
            is_virtual: false,
            capture_ready: true,
            capture_blocked_reason: None,
        }
    }
}

impl NetworkInterface {
    /// Creates an interface with the minimum required fields.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            ..Default::default()
        }
    }

    /// Primary IPv4 address, if any.
    #[must_use]
    pub fn primary_ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses.iter().find_map(|a| match a.addr {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
    }

    /// Primary global IPv6 address, preferring non-link-local addresses.
    #[must_use]
    pub fn primary_ipv6(&self) -> Option<Ipv6Addr> {
        self.addresses
            .iter()
            .filter_map(|a| match a.addr {
                IpAddr::V6(v6) => Some((a.is_link_local(), v6)),
                IpAddr::V4(_) => None,
            })
            .min_by_key(|(is_link_local, _)| *is_link_local)
            .map(|(_, v6)| v6)
    }

    /// Addresses joined for display, e.g. `192.168.1.10/24`.
    #[must_use]
    pub fn address_summary(&self) -> String {
        if self.addresses.is_empty() {
            return "No address".to_string();
        }
        self.addresses
            .iter()
            .map(|a| format!("{}/{}", a.addr, a.prefix_len))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// True when an address is in a range that must never leave the device.
#[must_use]
pub fn is_private_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_display_is_lowercase_colon_separated() {
        let mac = MacAddr::from_bytes([0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f]);
        assert_eq!(mac.to_string(), "1a:2b:3c:4d:5e:6f");
        assert_eq!(mac.oui(), [0x1a, 0x2b, 0x3c]);
    }

    #[test]
    fn mac_classification() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(!MacAddr::ZERO.is_broadcast());
        assert!(MacAddr::ZERO.is_zero());
        assert!(!MacAddr::BROADCAST.is_zero());
        assert!(MacAddr::from_bytes([0x01, 0, 0, 0, 0, 1]).is_multicast());
        assert!(!MacAddr::from_bytes([0x00, 0x1a, 0, 0, 0, 1]).is_multicast());
    }

    #[test]
    fn mac_parses_and_round_trips_through_json() {
        let mac = MacAddr::from_bytes([0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f]);
        assert_eq!(MacAddr::parse("1a:2b:3c:4d:5e:6f"), Some(mac));
        assert_eq!(MacAddr::parse("1A:2B:3C:4D:5E:6F"), Some(mac));
        assert_eq!(MacAddr::parse("1a:2b:3c"), None);

        let json = serde_json::to_string(&mac).expect("serialize");
        assert_eq!(json, "\"1a:2b:3c:4d:5e:6f\"");
        let parsed: MacAddr = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, mac);
        assert!(serde_json::from_str::<MacAddr>("\"nope\"").is_err());
    }

    #[test]
    fn primary_address_prefers_ipv4_and_global_ipv6() {
        let iface = NetworkInterface {
            addresses: vec![
                InterfaceAddress::new("fe80::1".parse().expect("valid link local"), 64),
                InterfaceAddress::new("192.168.1.10".parse().expect("valid v4"), 24),
                InterfaceAddress::new("2606:4700::1".parse().expect("valid v6"), 64),
            ],
            ..NetworkInterface::new("1", "Ethernet")
        };
        assert_eq!(
            iface.primary_ipv4().map(|addr| addr.to_string()).as_deref(),
            Some("192.168.1.10")
        );
        assert_eq!(
            iface.primary_ipv6().map(|addr| addr.to_string()).as_deref(),
            Some("2606:4700::1")
        );
        assert!(iface.address_summary().contains("192.168.1.10/24"));
    }

    #[test]
    fn private_ranges_cover_local_network_and_localhost() {
        for addr in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.0.2",
            "127.0.0.1",
            "fe80::1",
            "fd00::5",
        ] {
            assert!(
                is_private_addr(addr.parse().expect("valid address")),
                "{addr} should be private"
            );
        }
        for addr in ["8.8.8.8", "142.250.72.206", "2606:4700::1"] {
            assert!(
                !is_private_addr(addr.parse().expect("valid address")),
                "{addr} should be public"
            );
        }
    }
}
