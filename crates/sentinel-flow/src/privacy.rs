//! Address redaction for exported reports.
//!
//! # Why this exists
//!
//! `PrivacyConfig::redact_local_addresses_in_exports` has existed since v0.1 and was never
//! implemented. `sentinel export` opened the database and serialised flows without loading
//! configuration at all, so enabling the option changed nothing: an export labelled as
//! redacted contained the machine's own addressing, its LAN topology, and every private peer
//! it had spoken to.
//!
//! For a product whose central claim is local-first data handling, that is the worst possible
//! failure mode. It is silent, it is on the one path where a user hands data to somebody
//! else, and it fails *open* -- the user believes they are protected precisely when they are
//! not.
//!
//! # Why pseudonyms rather than a blanket replacement
//!
//! The naive redaction is to replace every private address with a constant. That is safe and
//! nearly useless: an analyst can no longer tell whether two flows involved the same peer, so
//! per-host byte totals, destination fan-out and lateral-movement patterns all collapse.
//!
//! So each distinct address gets a stable pseudonym, assigned in first-seen order:
//! `192.168.1.10` becomes `lan-1`, `192.168.1.11` becomes `lan-2`, and stays that way for
//! every row in the file. The addresses are gone, and the structure an investigation depends
//! on survives.
//!
//! Ports are deliberately kept. They carry no addressing information and are frequently the
//! thing being investigated.
//!
//! # What is considered private
//!
//! * **This machine** -- any address currently assigned to a local interface. Reported as
//!   `this-machine`.
//! * **Private range** -- RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`),
//!   link-local (`169.254/16`, `fe80::/10`) and loopback. Reported as `lan-N`.
//! * **Public** -- left untouched. A public destination IP is usually the most useful field in
//!   an export, and redacting it would gut the file without protecting anything meaningful.
//!
//! IPv6 unique-local (`fc00::/7`) is treated as private, as is the documentation range
//! (`2001:db8::/32`) -- the latter because it appears in documentation and test fixtures
//! where showing it would be misleading rather than revealing.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::key::Endpoint;

/// What an address was replaced with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redaction {
    /// One of this machine's own interface addresses.
    ThisMachine,
    /// A private-range peer, replaced by a stable per-export pseudonym.
    Pseudonym(String),
    /// Publicly routable, so kept as-is.
    Kept(IpAddr),
}

impl Redaction {
    /// The text to write into an export.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::ThisMachine => "this-machine".to_string(),
            Self::Pseudonym(name) => name.clone(),
            Self::Kept(addr) => addr.to_string(),
        }
    }
}

/// True for addresses that must not appear in an export verbatim.
///
/// `100.64.0.0/10` is included because carrier-grade NAT space is frequently the CGNAT range
/// of an ISP, which identifies the subscriber far more precisely than a public address does.
#[must_use]
pub fn is_private_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // CGNAT: 100.64.0.0/10
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Unique local: fc00::/7
            (segments[0] & 0xfe00) == 0xfc00
                // Link-local: fe80::/10
                || (segments[0] & 0xffc0) == 0xfe80
                || v6.is_loopback()
                || v6.is_unspecified()
                // Documentation: 2001:db8::/32
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

/// Rewrites addresses for export, keeping one pseudonym per distinct private peer.
///
/// A single instance covers one export file. It is not `Sync` because pseudonyms are
/// assigned on first sight, and sharing one across threads would make output depend on
/// ordering; each export builds its own.
///
/// See the module documentation for why pseudonyms are stable per address rather than a
/// single blanket replacement.
#[derive(Debug, Default)]
pub struct Redactor {
    machine_addresses: Vec<IpAddr>,
    pseudonyms: HashMap<IpAddr, String>,
}

impl Redactor {
    /// Builds a redactor that treats `machine_addresses` as this machine's own.
    #[must_use]
    pub fn new(machine_addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            machine_addresses: machine_addresses.into_iter().collect(),
            pseudonyms: HashMap::new(),
        }
    }

    /// True when nothing in the export would change, i.e. no private address can appear.
    ///
    /// Used to tell the user plainly that a setting had no effect, rather than leaving them
    /// to assume it worked.
    #[must_use]
    pub fn is_inert_for(&self, addresses: impl IntoIterator<Item = IpAddr>) -> bool {
        addresses
            .into_iter()
            .all(|addr| !self.machine_addresses.contains(&addr) && !is_private_address(addr))
    }

    /// Decides what to write for one address.
    pub fn redact(&mut self, addr: IpAddr) -> Redaction {
        if self.machine_addresses.contains(&addr) {
            return Redaction::ThisMachine;
        }
        if !is_private_address(addr) {
            return Redaction::Kept(addr);
        }
        let next = self.pseudonyms.len() + 1;
        let name = self
            .pseudonyms
            .entry(addr)
            .or_insert_with(|| format!("lan-{next}"))
            .clone();
        Redaction::Pseudonym(name)
    }

    /// Redacts one endpoint, preserving the port.
    pub fn redact_endpoint(&mut self, endpoint: &Endpoint) -> String {
        let address = self.redact(endpoint.addr).label();
        match endpoint.port {
            Some(port) if endpoint.addr.is_ipv6() => format!("[{address}]:{port}"),
            Some(port) => format!("{address}:{port}"),
            None => address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(text: &str) -> IpAddr {
        text.parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .expect("valid IPv6")
    }

    fn endpoint(addr: IpAddr, port: Option<u16>) -> Endpoint {
        Endpoint::new(addr, port)
    }

    #[test]
    fn private_ranges_are_recognised() {
        for addr in [
            v4(10, 0, 0, 1),
            v4(172, 16, 5, 4),
            v4(192, 168, 1, 10),
            v4(169, 254, 3, 2),
            v4(127, 0, 0, 1),
            v4(100, 100, 1, 1),
            v6("fe80::1"),
            v6("fd00::1"),
        ] {
            assert!(is_private_address(addr), "{addr} should be private");
        }
    }

    #[test]
    fn public_addresses_are_kept() {
        for addr in [v4(93, 184, 216, 34), v4(1, 1, 1, 1), v6("2606:4700::1")] {
            assert!(!is_private_address(addr), "{addr} should be public");
        }
    }

    #[test]
    fn the_172_16_boundary_is_exact() {
        // 172.15.x and 172.32.x are public; 172.16.x through 172.31.x are private.
        assert!(!is_private_address(v4(172, 15, 0, 1)));
        assert!(is_private_address(v4(172, 16, 0, 1)));
        assert!(is_private_address(v4(172, 31, 255, 255)));
        assert!(!is_private_address(v4(172, 32, 0, 1)));
    }

    #[test]
    fn a_private_peer_gets_one_stable_pseudonym() {
        let mut redactor = Redactor::default();
        let first = redactor.redact(v4(192, 168, 1, 10));
        let again = redactor.redact(v4(192, 168, 1, 10));
        let other = redactor.redact(v4(192, 168, 1, 11));

        assert_eq!(
            first, again,
            "the same address must map to the same pseudonym"
        );
        assert_ne!(first, other, "different addresses must not collide");
        assert_eq!(first.label(), "lan-1");
        assert_eq!(other.label(), "lan-2");
    }

    #[test]
    fn the_machine_is_named_rather_than_pseudonymed() {
        let mut redactor = Redactor::new([v4(192, 168, 1, 170)]);
        assert_eq!(
            redactor.redact(v4(192, 168, 1, 170)),
            Redaction::ThisMachine
        );
    }

    #[test]
    fn ports_survive_redaction() {
        let mut redactor = Redactor::default();
        let rendered = redactor.redact_endpoint(&endpoint(v4(192, 168, 1, 10), Some(52341)));
        assert_eq!(
            rendered, "lan-1:52341",
            "the port is useful and discloses nothing"
        );
    }

    #[test]
    fn ipv6_keeps_its_brackets_when_a_port_is_present() {
        // Without brackets, `lan-1:443` is fine but a kept IPv6 address would be ambiguous.
        let mut redactor = Redactor::default();
        assert_eq!(
            redactor.redact_endpoint(&endpoint(v6("fe80::1"), Some(443))),
            "[lan-1]:443"
        );
        assert_eq!(
            redactor.redact_endpoint(&endpoint(v6("2606:4700::1"), Some(443))),
            "[2606:4700::1]:443"
        );
    }

    #[test]
    fn a_portless_endpoint_has_no_separator() {
        let mut redactor = Redactor::default();
        assert_eq!(
            redactor.redact_endpoint(&endpoint(v4(10, 0, 0, 4), None)),
            "lan-1"
        );
    }

    #[test]
    fn public_destinations_are_untouched() {
        let mut redactor = Redactor::default();
        let rendered = redactor.redact_endpoint(&endpoint(v4(93, 184, 216, 34), Some(443)));
        assert_eq!(rendered, "93.184.216.34:443");
    }

    #[test]
    fn a_public_only_export_is_reported_as_untouched() {
        let redactor = Redactor::new([v4(192, 168, 1, 170)]);
        assert!(redactor.is_inert_for([v4(93, 184, 216, 34), v6("2606:4700::1")]));
        assert!(!redactor.is_inert_for([v4(192, 168, 1, 11)]));
    }

    #[test]
    fn redaction_is_stable_across_interleaved_addresses() {
        // Order of first sight assigns the numbers, but a peer's pseudonym never changes, so
        // byte totals per peer stay comparable across the whole file.
        let mut redactor = Redactor::default();
        assert_eq!(redactor.redact(v4(192, 168, 1, 10)).label(), "lan-1");
        assert_eq!(redactor.redact(v4(192, 168, 1, 11)).label(), "lan-2");
        assert_eq!(redactor.redact(v4(192, 168, 1, 10)).label(), "lan-1");
        assert_eq!(redactor.redact(v4(192, 168, 1, 12)).label(), "lan-3");
        assert_eq!(redactor.redact(v4(192, 168, 1, 11)).label(), "lan-2");
    }
}
