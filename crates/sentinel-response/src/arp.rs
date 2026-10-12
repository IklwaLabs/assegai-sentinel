//! ARP cache poisoning detection.
//!
//! # Why confirmation matters more than detection
//!
//! A naive ARP spoofing detector reports the first time it sees one MAC address claim an IP
//! that a different MAC held a moment ago. That is how every naive detector behaves, and it
//! is wrong often enough to be useless: DHCP leases legitimately move addresses between hosts,
//! a phone leaving WiFi frees an address that a laptop then takes, multi-homed machines answer
//! for more than one interface.
//!
//! A tool that cries wolf on a busy network gets muted, and a muted detector protects nothing.
//! So a conflict has to be *sustained* before it is reported: the incumbent has to answer for
//! the address, or the challenger has to win repeatedly, before anything is treated as an
//! attack.
//!
//! This is why the state machine below exists rather than a single `if previous != current`
//! check. It also means a short-lived DHCP handoff never reaches the remediation path, which
//! matters: remediating a legitimate re-address would disrupt a working machine.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use sentinel_common::net::MacAddr;
use sentinel_common::packet::{ArpMessage, ArpOpcode};

/// How many times a challenger must win while the incumbent stays silent before the takeover
/// is treated as real.
///
/// This is the fallback path, used when the incumbent has gone quiet and the "both answering"
/// signal can therefore never fire. Three is chosen so a single missed reply cannot trigger
/// it, and so a legitimate handoff -- which resolves within a couple of exchanges -- cannot
/// either.
const CHALLENGER_WINS_REQUIRED: u8 = 3;

/// One address and who currently claims it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Binding {
    mac: MacAddr,
    /// How many times the incumbent has answered for this address.
    confirmations: u8,
    /// A second MAC that started claiming this address, if one has appeared.
    challenger: Option<MacAddr>,
    /// How many times that challenger has claimed the address.
    challenger_wins: u8,
    /// How many times the incumbent has answered *since* the challenger appeared.
    ///
    /// This is the discriminator between a spoof and a re-address, and the whole reason the
    /// state is more than a counter. In a DHCP handoff the old holder goes quiet and stops
    /// answering. In an active spoof both machines keep answering for one address, so seeing
    /// the incumbent answer after the challenger appeared is close to proof.
    incumbent_after_challenger: u8,
}

/// Confidence in a detected conflict, which drives both severity and whether Sentinel is
/// willing to act on its own.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    /// One address, two MACs, seen once. Almost always a legitimate re-address.
    Possible,
    /// Sustained, with the incumbent still answering, or repeatedly beaten by the challenger.
    Confirmed,
}

/// A detected address conflict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpConflict {
    /// The address both MACs claim.
    pub ip: Ipv4Addr,
    /// The address as it was bound when the conflict began.
    #[serde(rename = "incumbentMac")]
    pub incumbent_mac: MacAddr,
    /// The address claiming to be it now.
    #[serde(rename = "challengerMac")]
    pub challenger_mac: MacAddr,
    /// How confident the detector is.
    pub confidence: Confidence,
    /// Total ARP messages observed for this address, as evidence in an alert.
    pub observations: u32,
    /// True when the incumbent is still answering, which is the strongest evidence: two hosts
    /// are answering for one address.
    #[serde(rename = "incumbentStillAnswering")]
    pub incumbent_still_answering: bool,
}

/// What the caller should do about a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not enough evidence to report. Counted so the UI can show progress rather than
    /// pretending nothing is happening.
    NotYet {
        /// Why it is being held back, for the interface to explain.
        reason: &'static str,
    },
    /// Report, with evidence.
    Report(ArpConflict),
}

/// Learns address bindings and reports sustained conflicts.
///
/// Deliberately free of any I/O and of any clock: time enters only as the caller passes
/// observations in order. That is what makes every rule below testable without a network, in
/// line with the rest of the suite.
#[derive(Debug, Default)]
pub struct ArpMonitor {
    bindings: HashMap<Ipv4Addr, Binding>,
    observations: u32,
}

/// Builds the report for a disputed address.
///
/// Both paths that decide to report go through here, so the evidence attached to an alert
/// is assembled in exactly one place and cannot drift between them.
///
/// A free function rather than a method: it is called while a Binding is mutably
/// borrowed out of the table, so it cannot also take &self.
fn conflict_for(ip: Ipv4Addr, binding: &Binding, observations: u32) -> ArpConflict {
    ArpConflict {
        ip,
        incumbent_mac: binding.mac,
        challenger_mac: binding.challenger.unwrap_or(MacAddr::ZERO),
        confidence: Confidence::Confirmed,
        observations,
        incumbent_still_answering: binding.incumbent_after_challenger > 0,
    }
}

impl ArpMonitor {
    /// Creates an empty monitor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one decoded ARP message and returns a verdict, if the message changed anything.
    ///
    /// Only messages that *claim* an address are considered. An ARP request asking who has an
    /// address carries the sender's own binding, which is still useful to learn, but the
    /// target field is a question rather than a claim and is never treated as one.
    pub fn observe(&mut self, arp: &ArpMessage) -> Verdict {
        // Only Ethernet over IPv4 is modelled; anything else is someone else's decoder.
        if arp.hardware_type != 1 || arp.protocol_type != 0x0800 {
            return Verdict::NotYet {
                reason: "not ethernet/ipv4 arp",
            };
        }

        // A zero sender MAC is how a sender says "I don't know my address yet". Learning a
        // binding from it would poison the table with a value nothing can own.
        if arp.sender_mac.is_zero() || arp.sender_mac.is_broadcast() {
            return Verdict::NotYet {
                reason: "sender address is unusable",
            };
        }

        self.observations = self.observations.saturating_add(1);

        // An ARP reply also asserts the target binding, so both halves are learned. This is
        // how a conflict gets noticed even when only replies are visible.
        //
        // The verdict from the *last* update is the meaningful one: if the target half of a
        // reply is what conflicts, that is the conflict worth reporting, and returning the
        // sender half's verdict would report the wrong address.
        let last = match arp.opcode {
            ArpOpcode::Reply => {
                let mut verdict = self.update(arp.sender_ip, arp.sender_mac);
                if !arp.target_mac.is_zero() && !arp.target_mac.is_broadcast() {
                    verdict = self.update(arp.target_ip, arp.target_mac);
                }
                verdict
            }
            ArpOpcode::Request | ArpOpcode::Other(_) => self.update(arp.sender_ip, arp.sender_mac),
        };
        if matches!(last, Verdict::Report(_)) {
            return last;
        }

        last
    }

    /// Applies one claim and reports it if it is sustained.
    fn update(&mut self, ip: Ipv4Addr, mac: MacAddr) -> Verdict {
        match self.bindings.get_mut(&ip) {
            None => {
                self.bindings.insert(
                    ip,
                    Binding {
                        mac,
                        confirmations: 1,
                        challenger: None,
                        challenger_wins: 0,
                        incumbent_after_challenger: 0,
                    },
                );
                Verdict::NotYet {
                    reason: "first time this address has been seen",
                }
            }
            Some(binding) if binding.mac == mac => {
                binding.confirmations = binding.confirmations.saturating_add(1);

                // The incumbent answering again while another MAC is also claiming the address
                // is the strongest signal available: two machines are answering for one IP.
                if binding.challenger.is_some() {
                    binding.incumbent_after_challenger =
                        binding.incumbent_after_challenger.saturating_add(1);
                    let observations = self.observations;
                    return Verdict::Report(conflict_for(ip, binding, observations));
                }

                Verdict::NotYet {
                    reason: "incumbent reconfirmed its address",
                }
            }
            Some(binding) => {
                // A third claimant is still just a third claimant; the first one is the one
                // that started the dispute and is the one worth naming.
                if binding.challenger.is_none() {
                    binding.challenger = Some(mac);
                }
                binding.challenger_wins = binding.challenger_wins.saturating_add(1);

                // Only the silent-incumbent path needs a count. If the incumbent is still
                // answering, the "both answering" branch above reports on the next frame from
                // it, which is both faster and more reliable than counting challenger wins.
                if binding.incumbent_after_challenger == 0
                    && binding.challenger_wins >= CHALLENGER_WINS_REQUIRED
                {
                    let observations = self.observations;
                    return Verdict::Report(conflict_for(ip, binding, observations));
                }

                Verdict::NotYet {
                    reason: "conflict not yet sustained; a single disagreement is usually a re-address",
                }
            }
        }
    }

    /// The MAC currently recorded for an address, if any.
    #[must_use]
    pub fn binding_for(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.bindings.get(&ip).map(|binding| binding.mac)
    }

    /// How many addresses are being tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.bindings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> MacAddr {
        MacAddr::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, last])
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, last)
    }

    fn arp(opcode: ArpOpcode, sender_ip: Ipv4Addr, sender_mac: MacAddr) -> ArpMessage {
        ArpMessage {
            opcode,
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: 6,
            protocol_len: 4,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::ZERO,
            target_ip: Ipv4Addr::UNSPECIFIED,
        }
    }

    #[test]
    fn the_first_sighting_of_an_address_is_not_a_conflict() {
        let mut monitor = ArpMonitor::new();
        assert_eq!(
            monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1))),
            Verdict::NotYet {
                reason: "first time this address has been seen"
            }
        );
        assert_eq!(monitor.binding_for(ip(1)), Some(mac(1)));
    }

    #[test]
    fn the_incumbent_repeating_is_not_a_conflict() {
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        assert!(matches!(
            monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1))),
            Verdict::NotYet { .. }
        ));
        assert_eq!(monitor.tracked(), 1);
    }

    #[test]
    fn a_single_disagreement_is_held_back() {
        // This is the whole point of the state machine. A phone leaving WiFi and a laptop
        // taking its address is not an attack, and remediating it would break a working
        // machine.
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        let verdict = monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2)));
        assert!(
            matches!(verdict, Verdict::NotYet { .. }),
            "one disagreement must not be reported, got {verdict:?}"
        );
    }

    #[test]
    fn two_hosts_answering_for_one_address_is_confirmed() {
        // The discriminator: the incumbent answers *after* the challenger appears. That is
        // what a real spoof looks like, and it is why detection does not need the challenger
        // to win several times.
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        assert!(matches!(
            monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2))),
            Verdict::NotYet { .. }
        ));
        match monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1))) {
            Verdict::Report(conflict) => {
                assert_eq!(conflict.ip, ip(1));
                assert_eq!(conflict.incumbent_mac, mac(1));
                assert_eq!(conflict.challenger_mac, mac(2));
                assert_eq!(conflict.confidence, Confidence::Confirmed);
                assert!(
                    conflict.incumbent_still_answering,
                    "the evidence must say the incumbent kept answering"
                );
            }
            other => panic!("expected a report, got {other:?}"),
        }
    }

    #[test]
    fn a_silent_incumbent_is_reported_only_after_repeated_wins() {
        // The other shape: the old holder goes quiet and the newcomer keeps claiming the
        // address. That is also what a DHCP handoff looks like, so it has to be sustained.
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        assert!(matches!(
            monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2))),
            Verdict::NotYet { .. }
        ));
        assert!(matches!(
            monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2))),
            Verdict::NotYet { .. }
        ));
        match monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2))) {
            Verdict::Report(conflict) => {
                assert_eq!(conflict.confidence, Confidence::Confirmed);
                assert!(
                    !conflict.incumbent_still_answering,
                    "the incumbent has not answered since the challenger appeared"
                );
            }
            other => panic!("expected a report, got {other:?}"),
        }
    }

    #[test]
    fn a_legitimate_handoff_is_never_reported() {
        // The case that would break a real network if it were mishandled: the old holder goes
        // away for good and the new one answers twice. That is two of the three wins, so it
        // stops short of the threshold and nothing is reported.
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        for _ in 0..2 {
            assert!(matches!(
                monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2))),
                Verdict::NotYet { .. }
            ));
        }
        assert!(!monitor.binding_for(ip(1)).is_none());
    }

    #[test]
    fn a_third_claimant_does_not_displace_the_named_one() {
        // The first challenger is the one that started the dispute; a third machine showing
        // up must not rewrite history to name it instead.
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(2)));
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(3)));
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(3)));
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(3)));
        match monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1))) {
            Verdict::Report(conflict) => assert_eq!(
                conflict.challenger_mac,
                mac(2),
                "the alert must name the MAC that began the conflict"
            ),
            other => panic!("expected a report, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_sender_mac_is_never_learned() {
        // Some senders fill it with zero to mean "unknown". Learning a binding from that
        // would put an address no device owns into the table.
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), MacAddr::ZERO));
        assert_eq!(monitor.tracked(), 0);
    }

    #[test]
    fn a_reply_teaches_both_sides() {
        let mut monitor = ArpMonitor::new();
        let mut reply = arp(ArpOpcode::Reply, ip(1), mac(1));
        reply.target_ip = ip(2);
        reply.target_mac = mac(2);
        monitor.observe(&reply);
        assert_eq!(monitor.binding_for(ip(1)), Some(mac(1)));
        assert_eq!(monitor.binding_for(ip(2)), Some(mac(2)));
        assert_eq!(monitor.tracked(), 2);
    }

    #[test]
    fn a_request_does_not_learn_its_target() {
        // The target of a request is a question, not a claim.
        let mut monitor = ArpMonitor::new();
        let mut request = arp(ArpOpcode::Request, ip(1), mac(1));
        request.target_ip = ip(9);
        request.target_mac = mac(9);
        monitor.observe(&request);
        assert_eq!(monitor.binding_for(ip(9)), None);
    }

    #[test]
    fn non_ethernet_or_non_ipv4_is_ignored() {
        let mut monitor = ArpMonitor::new();
        let mut odd = arp(ArpOpcode::Reply, ip(1), mac(1));
        odd.hardware_type = 6;
        monitor.observe(&odd);
        assert_eq!(monitor.tracked(), 0);
    }

    #[test]
    fn separate_addresses_do_not_interfere() {
        let mut monitor = ArpMonitor::new();
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        monitor.observe(&arp(ArpOpcode::Reply, ip(2), mac(2)));
        monitor.observe(&arp(ArpOpcode::Reply, ip(1), mac(1)));
        assert_eq!(monitor.tracked(), 2);
        assert_eq!(monitor.binding_for(ip(1)), Some(mac(1)));
    }
}
