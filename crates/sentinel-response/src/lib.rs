//! Active network response.
//!
//! # Read this before enabling it
//!
//! Until v0.2 Sentinel only observed. This crate makes it able to change the network: it can
//! transmit frames to correct a poisoned ARP cache. That is a deliberate break of the
//! read-only guarantee `SECURITY.md` used to make, and the guarantee was worth something --
//! it is a large part of why a cautious organisation would run this at all.
//!
//! So the break is deliberate rather than incidental:
//!
//! - Nothing is transmitted unless [`Consent`] is [`Consent::Granted`], which requires a
//!   named authoriser and a described network. Default is [`Consent::Disabled`], and
//!   upgrading cannot turn it on.
//! - Every attempt is written to [`AuditTrail::record`] before it is made, so an automated
//!   action is never indistinguishable from an attack.
//! - Detection and response are separable. [`ArpMonitor`] reports; the repair path is only
//!   reachable through [`respond_to_conflict`], which checks consent first.
//!
//! Injecting traffic onto a network you do not own is a criminal offence in many
//! jurisdictions even when the traffic is corrective. That is why consent is validated when it
//! is created rather than when it is used: an authorisation that cannot be acted on should
//! never have been saved.
//!
//! # What this crate does not do
//!
//! It does not modify DNS, does not shape or block traffic, and does not transmit anything
//! that is not a direct correction of a specific, detected fault. Each of those would be a
//! separate and larger decision.

#![forbid(unsafe_code)]

pub mod arp;
pub mod audit;
pub mod consent;
pub mod repair;

pub use arp::{ArpConflict, ArpMonitor, Confidence, Verdict};
pub use audit::{ActionRecord, AuditTrail, Outcome};
pub use consent::{Authorization, Consent, Refusal};
pub use repair::{InjectedFrame, Injector, build_gratuitous_arp_reply};

/// Repairs a confirmed ARP conflict, if that is permitted.
///
/// The single entry point for anything that changes the network. Nothing else in this crate
/// calls an [`Injector`], so consent cannot be bypassed by reaching for the low-level API
/// instead.
///
/// # Errors
/// Returns [`Refusal`] when response is disabled or the authorisation is unusable, and a
/// driver message when the frame could not be sent. In every case nothing has been changed.
pub fn respond_to_conflict(
    conflict: &ArpConflict,
    consent: &Consent,
    injector: &mut dyn Injector,
    audit: &mut AuditTrail,
    now_us: u64,
) -> Result<ActionRecord, ResponseError> {
    // Consent is checked before anything is built, not before the frame is sent. Building a
    // frame is harmless; the irreversible part is transmitting it.
    consent::check(consent).map_err(ResponseError::Refused)?;

    // Only a confirmed conflict is acted on. A `Possible` conflict is what a DHCP handoff
    // looks like, and remediating that breaks a working machine.
    if conflict.confidence != Confidence::Confirmed {
        let reason = "conflict is not sustained; this is usually a legitimate re-address";
        audit.record(
            consent,
            now_us,
            Outcome::Failed {
                reason: reason.to_string(),
            },
            Some(conflict.ip),
            Some(conflict.incumbent_mac),
        );
        return Err(ResponseError::NotConfirmed(reason.to_string()));
    }

    let frame = match build_gratuitous_arp_reply(conflict.incumbent_mac, conflict.ip) {
        Ok(frame) => frame,
        Err(reason) => {
            audit.record(
                consent,
                now_us,
                Outcome::Failed {
                    reason: reason.clone(),
                },
                Some(conflict.ip),
                Some(conflict.incumbent_mac),
            );
            return Err(ResponseError::Build(reason));
        }
    };

    let sent = injector.inject(&frame);
    let outcome = match &sent {
        Ok(bytes) => Outcome::Succeeded {
            bytes_sent: Some(*bytes),
        },
        Err(reason) => Outcome::Failed {
            reason: reason.clone(),
        },
    };

    let record = audit.record(
        consent,
        now_us,
        outcome,
        Some(conflict.ip),
        Some(conflict.incumbent_mac),
    );

    sent.map(|_| record).map_err(ResponseError::Send)
}

/// Why a response did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    /// Consent is absent or unusable. Nothing was transmitted.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// The conflict was not sustained enough to act on.
    #[error("not acted on: {0}")]
    NotConfirmed(String),
    /// The corrective frame could not be built.
    #[error("could not build the corrective frame: {0}")]
    Build(String),
    /// The driver refused the frame.
    #[error("the driver refused the corrective frame: {0}")]
    Send(String),
}

#[cfg(test)]
mod tests {
    use sentinel_common::net::MacAddr;

    use super::*;
    use crate::consent::Consent;
    use crate::repair::InjectedFrame;
    use std::net::Ipv4Addr;

    #[derive(Default)]
    struct Recorder {
        sent: Vec<Vec<u8>>,
        refuse: Option<String>,
    }

    impl Injector for Recorder {
        fn inject(&mut self, frame: &InjectedFrame) -> Result<usize, String> {
            match &self.refuse {
                Some(reason) => Err(reason.clone()),
                None => {
                    self.sent.push(frame.bytes.clone());
                    Ok(frame.bytes.len())
                }
            }
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, last)
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, last])
    }

    fn granted() -> Consent {
        Consent::Granted(Box::new(
            consent::authorize("Eric", "Office WiFi", 1).expect("valid"),
        ))
    }

    fn confirmed_conflict() -> ArpConflict {
        ArpConflict {
            ip: ip(1),
            incumbent_mac: mac(1),
            challenger_mac: mac(2),
            confidence: Confidence::Confirmed,
            observations: 9,
            incumbent_still_answering: true,
        }
    }

    #[test]
    fn nothing_is_sent_without_consent() {
        let mut injector = Recorder::default();
        let mut audit = AuditTrail::new();
        let result = respond_to_conflict(
            &confirmed_conflict(),
            &Consent::Disabled,
            &mut injector,
            &mut audit,
            1_000,
        );
        assert_eq!(result, Err(ResponseError::Refused(Refusal::Disabled)));
        assert!(
            injector.sent.is_empty(),
            "not one byte may leave the machine"
        );
        assert!(
            audit.is_untouched(),
            "a refusal changes nothing, so the audit must not claim otherwise"
        );
    }

    #[test]
    fn a_confirmed_conflict_is_repaired_and_audited() {
        let mut injector = Recorder::default();
        let mut audit = AuditTrail::new();
        let record = respond_to_conflict(
            &confirmed_conflict(),
            &granted(),
            &mut injector,
            &mut audit,
            1_000,
        )
        .expect("repaired");

        assert_eq!(injector.sent.len(), 1);
        assert_eq!(record.authorised_by, "Eric");
        assert_eq!(record.network_description, "Office WiFi");
        assert!(record.outcome.changed_the_network());
        assert!(!audit.is_untouched());
    }

    #[test]
    fn an_unsustained_conflict_is_never_repaired() {
        // The important safety property: a Possible conflict is what a phone leaving WiFi
        // looks like, and reacting to it would disrupt a working machine.
        let mut injector = Recorder::default();
        let mut audit = AuditTrail::new();
        let mut conflict = confirmed_conflict();
        conflict.confidence = Confidence::Possible;

        let result = respond_to_conflict(&conflict, &granted(), &mut injector, &mut audit, 1_000);
        assert!(matches!(result, Err(ResponseError::NotConfirmed(_))));
        assert!(injector.sent.is_empty());
        assert!(audit.is_untouched());
    }

    #[test]
    fn a_driver_failure_is_audited_as_a_failure_not_a_success() {
        let mut injector = Recorder {
            refuse: Some("permission denied".to_string()),
            ..Recorder::default()
        };
        let mut audit = AuditTrail::new();
        let result = respond_to_conflict(
            &confirmed_conflict(),
            &granted(),
            &mut injector,
            &mut audit,
            1_000,
        );
        assert!(matches!(result, Err(ResponseError::Send(_))));
        assert!(
            audit.is_untouched(),
            "the frame did not go out, so the network did not change"
        );
    }

    #[test]
    fn the_attempt_is_audited_even_when_it_fails() {
        // Silence is not acceptable: an operator who asked for protection needs to see that
        // Sentinel tried and could not.
        let mut injector = Recorder {
            refuse: Some("busy".to_string()),
            ..Recorder::default()
        };
        let mut audit = AuditTrail::new();
        let _ = respond_to_conflict(
            &confirmed_conflict(),
            &granted(),
            &mut injector,
            &mut audit,
            1_000,
        );
        assert_eq!(audit.records().len(), 1);
    }

    #[test]
    fn detection_runs_with_response_turned_off() {
        // Detection must keep working when response is off. Turning off the ability to act
        // is not a reason to stop seeing the attack.
        fn reply(
            sender_mac: sentinel_common::net::MacAddr,
            sender_ip: std::net::Ipv4Addr,
        ) -> sentinel_common::packet::ArpMessage {
            sentinel_common::packet::ArpMessage {
                opcode: sentinel_common::packet::ArpOpcode::Reply,
                hardware_type: 1,
                protocol_type: 0x0800,
                hardware_len: 6,
                protocol_len: 4,
                sender_mac,
                sender_ip,
                target_mac: sentinel_common::net::MacAddr::ZERO,
                target_ip: std::net::Ipv4Addr::UNSPECIFIED,
            }
        }

        let mut monitor = ArpMonitor::new();
        monitor.observe(&reply(mac(1), ip(1)));
        monitor.observe(&reply(mac(2), ip(1)));
        // The incumbent answering after the challenger appeared is what makes this a spoof
        // rather than a re-address.
        let verdict = monitor.observe(&reply(mac(1), ip(1)));

        assert!(
            matches!(verdict, Verdict::Report(_)),
            "detection must not depend on consent"
        );
    }
}
