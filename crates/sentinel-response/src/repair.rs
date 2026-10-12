//! Constructing and sending a corrective ARP announcement.
//!
//! # What this does and does not do
//!
//! When two hosts answer for one address, hosts on the segment can cache the wrong
//! association and keep sending traffic to the impostor. The standard repair is a
//! *gratuitous ARP reply*: an unsolicited broadcast that re-asserts the true binding, so
//! every host updates its cache without needing to be attacked again first.
//!
//! This module builds that frame. It is a pure function over bytes, so the exact wire format
//! is testable without a network adapter, which is the only way to get it genuinely right --
//! a frame that is one byte short silently repairs nothing.
//!
//! # Why it is built here and sent elsewhere
//!
//! Building is separated from sending on purpose. The bytes are produced by this crate, which
//! has no privilege and no driver; the send is performed by `sentinel-capture` through
//! [`Injector`], which owns the pcap handle. That keeps the only platform-specific and
//! privilege-requiring part in the one crate that already has it, and keeps this logic
//! testable on any machine.

use std::net::Ipv4Addr;

use sentinel_common::net::MacAddr;
use sentinel_common::packet::ArpMessage;

/// EtherType for ARP, as it appears in an Ethernet II header.
const ETHERTYPE_ARP: u16 = 0x0806;

/// Size of the Ethernet II header.
const ETHERNET_HEADER_LEN: usize = 14;

/// Size of an Ethernet/IPv4 ARP message.
const ARP_MESSAGE_LEN: usize = 28;

/// A built frame, ready to hand to an [`Injector`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedFrame {
    /// Complete Ethernet frame, header included.
    pub bytes: Vec<u8>,
    /// Why the frame is being sent, recorded in the audit trail.
    pub reason: &'static str,
}

/// Something able to put a frame on the wire.
///
/// Implemented by `sentinel-capture`. Having it as a trait here means the response logic is
/// testable against a recorder that never touches a driver, and that an unauthorised call
/// site cannot reach the real implementation without passing consent first.
pub trait Injector {
    /// Sends one frame, returning the number of bytes written.
    ///
    /// # Errors
    /// Returns a message suitable for display when the driver refuses.
    fn inject(&mut self, frame: &InjectedFrame) -> Result<usize, String>;
}

/// Builds a gratuitous ARP reply re-asserting `ip` belongs to `mac`.
///
/// Sent from `mac` to the broadcast address, with the sender and target protocol addresses
/// both set to `ip`. That is what makes it *gratuitous*: no one asked, and every listener
/// treats it as an authoritative update for `ip`.
///
/// `ethertype` is not a parameter: ARP over IPv4/Ethernet is the only combination that exists
/// in practice, and allowing a caller to build a frame that nothing would understand would be
/// a way to fail silently.
///
/// # Errors
/// Returns a message when `mac` is not usable as a source address, because a frame from the
/// zero or broadcast address cannot repair anything and would only add noise to the segment.
pub fn build_gratuitous_arp_reply(mac: MacAddr, ip: Ipv4Addr) -> Result<InjectedFrame, String> {
    if mac.is_zero() {
        return Err("cannot announce an address owned by the zero MAC".to_string());
    }
    if mac.is_broadcast() {
        return Err("cannot announce an address owned by the broadcast MAC".to_string());
    }

    let mut bytes = Vec::with_capacity(ETHERNET_HEADER_LEN + ARP_MESSAGE_LEN);

    // Ethernet header: broadcast destination, our MAC as source, ARP ethertype.
    bytes.extend_from_slice(&MacAddr::BROADCAST.0);
    bytes.extend_from_slice(&mac.0);
    bytes.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    // ARP payload. Sender and target protocol addresses are both `ip`; the target hardware
    // address is zero, because in a gratuitous reply no one asked.
    bytes.extend_from_slice(&1u16.to_be_bytes()); // hardware type: Ethernet
    bytes.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol type: IPv4
    bytes.push(6); // hardware length
    bytes.push(4); // protocol length
    bytes.extend_from_slice(&2u16.to_be_bytes()); // opcode: reply
    bytes.extend_from_slice(&mac.0); // sender hardware address
    bytes.extend_from_slice(&ip.octets()); // sender protocol address
    bytes.extend_from_slice(&MacAddr::ZERO.0); // target hardware address
    bytes.extend_from_slice(&ip.octets()); // target protocol address

    debug_assert_eq!(bytes.len(), ETHERNET_HEADER_LEN + ARP_MESSAGE_LEN);

    Ok(InjectedFrame {
        bytes,
        reason: "re-assert a contested ARP binding",
    })
}

/// True when this message is one the response layer may learn a binding from.
#[must_use]
pub fn is_binding_claim(arp: &ArpMessage) -> bool {
    arp.hardware_type == 1
        && arp.protocol_type == 0x0800
        && !arp.sender_mac.is_zero()
        && !arp.sender_mac.is_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> MacAddr {
        MacAddr::from_bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, last])
    }

    #[test]
    fn the_frame_is_exactly_the_right_size() {
        let frame =
            build_gratuitous_arp_reply(mac(1), Ipv4Addr::new(192, 168, 1, 1)).expect("build");
        assert_eq!(
            frame.bytes.len(),
            ETHERNET_HEADER_LEN + ARP_MESSAGE_LEN,
            "a short frame is not a short ARP message; it is a repair that never happens"
        );
    }

    #[test]
    fn it_is_broadcast_so_every_host_hears_it() {
        let frame =
            build_gratuitous_arp_reply(mac(1), Ipv4Addr::new(192, 168, 1, 1)).expect("build");
        assert_eq!(
            &frame.bytes[0..6],
            &[0xff; 6],
            "destination must be broadcast"
        );
    }

    #[test]
    fn the_source_mac_is_the_repaired_owner() {
        let owner = mac(1);
        let frame =
            build_gratuitous_arp_reply(owner, Ipv4Addr::new(192, 168, 1, 1)).expect("build");
        assert_eq!(&frame.bytes[6..12], &owner.0);
    }

    #[test]
    fn the_ethertype_is_arp() {
        let frame =
            build_gratuitous_arp_reply(mac(1), Ipv4Addr::new(192, 168, 1, 1)).expect("build");
        assert_eq!(
            u16::from_be_bytes([frame.bytes[12], frame.bytes[13]]),
            ETHERTYPE_ARP
        );
    }

    #[test]
    fn the_arp_header_is_well_formed() {
        let frame =
            build_gratuitous_arp_reply(mac(1), Ipv4Addr::new(192, 168, 1, 1)).expect("build");
        let body = &frame.bytes[ETHERNET_HEADER_LEN..];
        assert_eq!(
            u16::from_be_bytes([body[0], body[1]]),
            1,
            "hardware type Ethernet"
        );
        assert_eq!(
            u16::from_be_bytes([body[2], body[3]]),
            0x0800,
            "protocol type IPv4"
        );
        assert_eq!(body[4], 6, "hardware length");
        assert_eq!(body[5], 4, "protocol length");
        assert_eq!(u16::from_be_bytes([body[6], body[7]]), 2, "opcode reply");
    }

    #[test]
    fn sender_and_target_protocol_address_are_the_same() {
        // This is what makes it gratuitous rather than a reply: no one asked, so both sides
        // name the same address and every listener treats it as an update.
        let ip = Ipv4Addr::new(10, 0, 0, 7);
        let frame = build_gratuitous_arp_reply(mac(1), ip).expect("build");
        let body = &frame.bytes[ETHERNET_HEADER_LEN..];
        assert_eq!(&body[14..18], &ip.octets(), "sender protocol address");
        assert_eq!(&body[24..28], &ip.octets(), "target protocol address");
        assert_eq!(
            &body[8..14],
            &owner_bytes(mac(1))[..],
            "sender hardware address"
        );
        assert_eq!(&body[18..24], &[0u8; 6], "target hardware address is unset");
    }

    fn owner_bytes(value: MacAddr) -> [u8; 6] {
        value.0
    }

    #[test]
    fn an_unusable_source_mac_is_refused() {
        assert!(build_gratuitous_arp_reply(MacAddr::ZERO, Ipv4Addr::LOCALHOST).is_err());
        assert!(build_gratuitous_arp_reply(MacAddr::BROADCAST, Ipv4Addr::LOCALHOST).is_err());
    }

    #[test]
    fn the_frame_carries_a_reason_for_the_audit_trail() {
        let frame = build_gratuitous_arp_reply(mac(1), Ipv4Addr::LOCALHOST).expect("build");
        assert!(!frame.reason.is_empty());
    }

    #[test]
    fn a_zero_sender_is_not_a_binding_claim() {
        let mut arp = sentinel_common::packet::ArpMessage {
            opcode: sentinel_common::packet::ArpOpcode::Reply,
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: 6,
            protocol_len: 4,
            sender_mac: MacAddr::ZERO,
            sender_ip: Ipv4Addr::LOCALHOST,
            target_mac: MacAddr::ZERO,
            target_ip: Ipv4Addr::UNSPECIFIED,
        };
        assert!(!is_binding_claim(&arp));
        arp.sender_mac = mac(1);
        assert!(is_binding_claim(&arp));
    }
}
