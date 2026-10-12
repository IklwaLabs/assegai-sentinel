//! The audit trail for anything Sentinel changes on a network.
//!
//! An automated action taken on someone's network must be reconstructable afterwards: what
//! was done, to which address, on whose authority, and what it was responding to. Without
//! that, an action is indistinguishable from an attack, which is precisely the situation the
//! action was meant to end.
//!
//! So every action appends here before it is attempted, records the outcome, and the records
//! are the product's own source of truth -- not a log line somewhere. They serialise, they
//! persist, and they are what an operator reads when they ask "what did Sentinel do?".

use sentinel_common::net::MacAddr;

/// What Sentinel attempted to do.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRecord {
    /// Monotonic identifier within the session, so records can be referred to unambiguously.
    pub sequence: u64,
    /// The action, named in the past tense: "re-asserted an ARP binding".
    pub action: String,
    /// Human-readable explanation, shown without needing to read the rest.
    pub summary: String,
    /// Who authorised it.
    #[serde(rename = "authorisedBy")]
    pub authorised_by: String,
    /// The network it was authorised for.
    #[serde(rename = "networkDescription")]
    pub network_description: String,
    /// When, as Unix microseconds.
    pub at_us: u64,
    /// The result.
    pub outcome: Outcome,
    /// The address the action concerned, when it concerned one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<std::net::Ipv4Addr>,
    /// The hardware address the action concerned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// Failure detail, when there was any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What happened to an action.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "camelCase")]
pub enum Outcome {
    /// The action completed.
    Succeeded {
        /// Bytes placed on the wire, when the action transmits something.
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes_sent: Option<usize>,
    },
    /// The action was refused or failed. Nothing was changed.
    Failed {
        /// Why.
        reason: String,
    },
}

impl Outcome {
    /// True when the network was actually changed.
    #[must_use]
    pub fn changed_the_network(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }
}

/// An append-only log of everything Sentinel has done to the network.
#[derive(Debug, Default)]
pub struct AuditTrail {
    records: Vec<ActionRecord>,
    next_sequence: u64,
}

impl AuditTrail {
    /// Creates an empty trail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a completed action and returns the stored record.
    ///
    /// The authoriser is read *out of* `consent` rather than passed in beside it. Taking the
    /// name separately would let a caller record an action under one name while consent was
    /// granted by another, and the audit would then disagree with the only record of who
    /// authorised what. This is also why the parameter is not optional: there is no version
    /// of this call that documents an action nobody consented to.
    pub fn record(
        &mut self,
        consent: &crate::consent::Consent,
        at_us: u64,
        outcome: Outcome,
        ip: Option<std::net::Ipv4Addr>,
        mac: Option<MacAddr>,
    ) -> ActionRecord {
        // Disabled consent has no authoriser to take. Callers gate on consent before acting,
        // so in practice this is unreachable; it exists so a record is never silently dropped,
        // which would be a worse failure than an obviously-wrong one.
        let (authorised_by, network_description) = match consent {
            crate::consent::Consent::Granted(authorization) => (
                authorization.authorised_by.clone(),
                authorization.network_description.clone(),
            ),
            crate::consent::Consent::Disabled => (
                "<no authoriser: response was disabled>".to_string(),
                "<none>".to_string(),
            ),
        };

        let record = ActionRecord {
            sequence: self.next_sequence,
            action: "re-asserted an ARP binding".to_string(),
            summary: "Restored a contested address to its true owner".to_string(),
            authorised_by,
            network_description,
            at_us,
            outcome,
            ip,
            mac,
            error: None,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.records.push(record.clone());
        record
    }

    /// Every record, oldest first.
    #[must_use]
    pub fn records(&self) -> &[ActionRecord] {
        &self.records
    }

    /// True when nothing has ever been changed. Used to show "Sentinel has not modified
    /// anything" rather than leaving it to be assumed.
    #[must_use]
    pub fn is_untouched(&self) -> bool {
        !self.records.iter().any(|r| r.outcome.changed_the_network())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn granted() -> crate::consent::Consent {
        crate::consent::Consent::Granted(Box::new(
            crate::consent::authorize("Eric", "Office WiFi", 1).expect("valid"),
        ))
    }

    fn ip() -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(192, 168, 1, 1)
    }

    fn mac() -> MacAddr {
        MacAddr::from_bytes([1, 2, 3, 4, 5, 6])
    }

    #[test]
    fn a_fresh_trail_has_changed_nothing() {
        assert!(AuditTrail::new().is_untouched());
    }

    #[test]
    fn a_successful_action_is_recorded_with_its_authority() {
        let mut trail = AuditTrail::new();
        let record = trail.record(
            &granted(),
            1_000,
            Outcome::Succeeded {
                bytes_sent: Some(42),
            },
            Some(ip()),
            Some(mac()),
        );
        assert_eq!(record.sequence, 0);
        assert_eq!(record.authorised_by, "Eric");
        assert_eq!(record.network_description, "Office WiFi");
        assert!(record.outcome.changed_the_network());
        assert_eq!(trail.records().len(), 1);
        assert!(!trail.is_untouched());
    }

    #[test]
    fn a_failed_action_does_not_claim_the_network_changed() {
        // The distinction matters: "we tried and could not" and "we changed it" must never
        // read the same in an audit.
        let mut trail = AuditTrail::new();
        trail.record(
            &granted(),
            1_000,
            Outcome::Failed {
                reason: "driver refused".to_string(),
            },
            Some(ip()),
            Some(mac()),
        );
        assert!(trail.is_untouched());
    }

    #[test]
    fn sequence_numbers_increase_so_records_can_be_referenced() {
        let mut trail = AuditTrail::new();
        for expected in 0..3u64 {
            let record = trail.record(
                &granted(),
                1_000,
                Outcome::Succeeded { bytes_sent: None },
                None,
                None,
            );
            assert_eq!(record.sequence, expected);
        }
    }

    #[test]
    fn a_record_round_trips_through_json() {
        let mut trail = AuditTrail::new();
        let record = trail.record(
            &granted(),
            42,
            Outcome::Succeeded {
                bytes_sent: Some(42),
            },
            Some(ip()),
            Some(mac()),
        );
        let json = serde_json::to_string(&record).expect("serialize");
        let back: ActionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn absent_optional_fields_are_omitted_rather_than_nulled() {
        let mut trail = AuditTrail::new();
        let record = trail.record(
            &granted(),
            42,
            Outcome::Succeeded { bytes_sent: None },
            None,
            None,
        );
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(
            !json.contains("\"ip\""),
            "unset fields should not appear: {json}"
        );
    }
}
