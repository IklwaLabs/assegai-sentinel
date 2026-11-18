//! The internal shape a detector hands to the engine.
//!
//! Separate from [`crate::Finding`] because a detector describes one *event*: the numbers it
//! measured and the advice that follows from them. The engine turns repeated events into one
//! finding. Keeping the two types apart is what stops a detector from having to know about
//! identity, deduplication or the cap on how many findings are retained.

use std::net::IpAddr;

use crate::finding::{Confidence, Evidence, FindingKind, Severity};

/// One detection event, before the engine folds it into a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    /// Stable identity: repeated events with the same id update one finding.
    pub id: String,
    /// What kind of behaviour this is.
    pub kind: FindingKind,
    /// Worst-case impact if real.
    pub severity: Severity,
    /// How sure the detector is that the behaviour is real.
    pub confidence: Confidence,
    /// One line naming the behaviour and the parties involved.
    pub title: String,
    /// What was seen, with the numbers behind it.
    pub detail: String,
    /// The address that caused the behaviour.
    pub source: Option<IpAddr>,
    /// The address affected.
    pub destination: Option<IpAddr>,
    /// When it was observed, as Unix microseconds.
    pub at_us: u64,
    /// The facts behind it.
    pub evidence: Vec<Evidence>,
    /// What the operator should do next.
    pub advice: Vec<&'static str>,
}

impl Observation {
    /// Advice as owned strings, which is what a finding stores.
    pub(crate) fn advice_strings(&self) -> Vec<String> {
        self.advice.iter().map(|line| (*line).to_string()).collect()
    }
}
