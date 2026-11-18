//! What Sentinel decided was worth telling you about.
//!
//! # A finding is not an accusation
//!
//! Every detector in this crate is a heuristic running on one host's view of one network. It
//! can be wrong, and in a way that matters: a port scan detector that fires on a browser is
//! noise, an exfiltration detector that fires on a cloud backup is a false alarm that teaches
//! the operator to ignore the real one.
//!
//! So a finding carries three separate judgements rather than one blended "threat score":
//!
//! - [`Severity`]: how much damage the behaviour could cause if it is real.
//! - [`Confidence`]: how sure Sentinel is that the behaviour is real, as opposed to normal
//!   traffic that happens to look similar.
//! - [`Finding::advice`]: what a person should actually do next, in plain language.
//!
//! These are deliberately not collapsed. A port scan from an external address is high severity
//! and high confidence and needs no judgement call. A large upload is high severity and medium
//! confidence: it might be ransomware staging, and it might be the nightly backup. Presenting
//! both as "critical" would be dishonest about the second.
//!
//! Nothing here mutates the network. Detection and response are separate by construction; see
//! `sentinel-response` for the part that can act, and `SECURITY.md` for when it is permitted.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// How much damage the behaviour could cause if it is real.
///
/// Ordered from least to most severe, so the derived `Ord` can be used to keep the highest
/// severity when two observations of the same finding disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    /// Worth knowing, not worth acting on.
    Info,
    /// A weakness or a bad practice, not an attack in progress.
    Low,
    /// Warrants attention; may be legitimate.
    Medium,
    /// Strongly suggests an attack or a serious exposure.
    High,
    /// Indicates the machine itself, or the network's path to it, is compromised.
    Critical,
}

impl Severity {
    /// Lower-case label used in storage and in the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Title-case label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    /// Numeric rank, ascending with severity.
    ///
    /// The same order as the derived `Ord`, exposed as a number so storage can sort by severity
    /// without knowing Rust's enum layout. It is defined here, next to the variants, because a
    /// second definition elsewhere would eventually disagree with this one.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    /// Parses a stored or transmitted label, returning `None` for anything unrecognised.
    ///
    /// Unknown values are rejected rather than defaulted: a severity that cannot be understood
    /// must not silently become "info", because that is how a real alert disappears.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// How sure Sentinel is that the behaviour is real rather than a look-alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    /// Plausible, and commonly benign.
    Low,
    /// Consistent with the pattern, but the pattern has ordinary explanations.
    Medium,
    /// The behaviour itself is unambiguous, even if its intent is not.
    High,
}

impl Confidence {
    /// Lower-case label used in storage and in the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Title-case label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }

    /// Parses a stored label, returning `None` for anything unrecognised.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// The kinds of behaviour Sentinel detects.
///
/// Stable identifiers: they are written to storage and sent to the interface, so renaming a
/// variant's serialised form would orphan every stored row of that kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    /// Two devices answering for one IPv4 address, or one address changing owner.
    ArpSpoofing,
    /// One host probing many ports on another.
    PortScan,
    /// One host probing one port across many hosts.
    HostSweep,
    /// A TCP header combination that ordinary stacks do not produce.
    TcpFlagAnomaly,
    /// A protocol that sends credentials or content without encryption.
    CleartextProtocol,
    /// Connections to one destination at a regular interval, the shape of command-and-control.
    PossibleBeaconing,
    /// A large one-directional upload to the internet.
    LargeOutboundTransfer,
}

impl FindingKind {
    /// Stable identifier used in storage and in the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArpSpoofing => "arpSpoofing",
            Self::PortScan => "portScan",
            Self::HostSweep => "hostSweep",
            Self::TcpFlagAnomaly => "tcpFlagAnomaly",
            Self::CleartextProtocol => "cleartextProtocol",
            Self::PossibleBeaconing => "possibleBeaconing",
            Self::LargeOutboundTransfer => "largeOutboundTransfer",
        }
    }

    /// Human label for the interface.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ArpSpoofing => "ARP spoofing",
            Self::PortScan => "Port scan",
            Self::HostSweep => "Host sweep",
            Self::TcpFlagAnomaly => "TCP flag anomaly",
            Self::CleartextProtocol => "Cleartext protocol",
            Self::PossibleBeaconing => "Possible beaconing",
            Self::LargeOutboundTransfer => "Large outbound transfer",
        }
    }

    /// Parses a stored identifier, returning `None` for anything unrecognised.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "arpSpoofing" => Some(Self::ArpSpoofing),
            "portScan" => Some(Self::PortScan),
            "hostSweep" => Some(Self::HostSweep),
            "tcpFlagAnomaly" => Some(Self::TcpFlagAnomaly),
            "cleartextProtocol" => Some(Self::CleartextProtocol),
            "possibleBeaconing" => Some(Self::PossibleBeaconing),
            "largeOutboundTransfer" => Some(Self::LargeOutboundTransfer),
            _ => None,
        }
    }
}

/// One fact supporting a finding.
///
/// Kept as label/value pairs rather than free text so an interface can render evidence as a
/// definition list and a report can export it without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// What the value is, e.g. "Distinct ports contacted".
    pub label: String,
    /// The value, already formatted for display.
    pub value: String,
}

impl Evidence {
    /// Builds an evidence row.
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

/// Something Sentinel observed and decided was worth reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable identity, so repeated observations update one finding instead of flooding the list.
    pub id: String,
    /// What kind of behaviour this is.
    pub kind: FindingKind,
    /// Worst-case impact if real.
    pub severity: Severity,
    /// How sure Sentinel is that it is real.
    pub confidence: Confidence,
    /// One line naming the behaviour and the parties involved.
    pub title: String,
    /// What was seen, in plain language, including the numbers behind it.
    pub detail: String,
    /// The address that caused the behaviour, when it is identifiable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<IpAddr>,
    /// The address affected, when it is identifiable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<IpAddr>,
    /// First observation, as Unix microseconds.
    pub first_seen_us: u64,
    /// Most recent observation, as Unix microseconds.
    pub last_seen_us: u64,
    /// How many times the behaviour was observed after the finding was first raised.
    pub occurrences: u64,
    /// The facts behind the finding.
    pub evidence: Vec<Evidence>,
    /// What the operator should do, in the order worth doing it.
    pub advice: Vec<String>,
}

impl Finding {
    /// Orders findings for display: most severe first, then most recent.
    ///
    /// Used everywhere a list is shown, so the interface and an export cannot disagree about
    /// what "top of the list" means.
    pub fn sort_for_display(findings: &mut [Finding]) {
        findings.sort_by(Self::display_order);
    }

    /// The comparison behind [`Finding::sort_for_display`].
    ///
    /// Exposed so callers can order references and clone only what they will show. A snapshot
    /// is taken several times a second, and cloning every finding to sort it would allocate on
    /// a timer for no reason.
    #[must_use]
    pub fn display_order(a: &Self, b: &Self) -> std::cmp::Ordering {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.last_seen_us.cmp(&a.last_seen_us))
            .then_with(|| a.id.cmp(&b.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_puts_critical_last_so_max_wins() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::Info.max(Severity::High), Severity::High);
    }

    #[test]
    fn numeric_rank_agrees_with_the_derived_ordering() {
        // Storage sorts by the number. If the two ever disagree, a critical finding could be
        // sorted below an informational one, so the relationship is asserted rather than
        // assumed.
        let ordered = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for pair in ordered.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(
                pair[0].rank() < pair[1].rank(),
                "rank must follow Ord for {:?} and {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn every_severity_and_confidence_round_trips_through_its_label() {
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }
        for confidence in [Confidence::Low, Confidence::Medium, Confidence::High] {
            assert_eq!(Confidence::parse(confidence.as_str()), Some(confidence));
        }
    }

    #[test]
    fn an_unknown_label_is_rejected_rather_than_defaulted() {
        // Defaulting to Info would turn an unreadable row into a silently-dismissed alert.
        assert_eq!(Severity::parse("catastrophic"), None);
        assert_eq!(Confidence::parse(""), None);
        assert_eq!(FindingKind::parse("somethingElse"), None);
    }

    #[test]
    fn every_kind_round_trips_and_has_a_distinct_identifier() {
        let kinds = [
            FindingKind::ArpSpoofing,
            FindingKind::PortScan,
            FindingKind::HostSweep,
            FindingKind::TcpFlagAnomaly,
            FindingKind::CleartextProtocol,
            FindingKind::PossibleBeaconing,
            FindingKind::LargeOutboundTransfer,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for kind in kinds {
            assert_eq!(FindingKind::parse(kind.as_str()), Some(kind));
            assert!(
                seen.insert(kind.as_str()),
                "two kinds share the identifier {}",
                kind.as_str()
            );
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn display_order_is_severity_then_recency() {
        let make = |id: &str, severity, last_seen_us| Finding {
            id: id.to_string(),
            kind: FindingKind::PortScan,
            severity,
            confidence: Confidence::High,
            title: String::new(),
            detail: String::new(),
            source: None,
            destination: None,
            first_seen_us: 0,
            last_seen_us,
            occurrences: 1,
            evidence: Vec::new(),
            advice: Vec::new(),
        };

        let mut findings = vec![
            make("low-new", Severity::Low, 300),
            make("high-old", Severity::High, 100),
            make("high-new", Severity::High, 200),
            make("low-old", Severity::Low, 50),
        ];
        Finding::sort_for_display(&mut findings);
        let order: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(order, ["high-new", "high-old", "low-new", "low-old"]);
    }

    #[test]
    fn a_finding_round_trips_through_json_without_inventing_addresses() {
        let finding = Finding {
            id: "portScan|10.0.0.5|10.0.0.9".to_string(),
            kind: FindingKind::PortScan,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Port scan".to_string(),
            detail: "detail".to_string(),
            source: Some("10.0.0.5".parse().expect("valid")),
            destination: None,
            first_seen_us: 1,
            last_seen_us: 2,
            occurrences: 3,
            evidence: vec![Evidence::new("Distinct ports", "24")],
            advice: vec!["Investigate".to_string()],
        };
        let json = serde_json::to_string(&finding).expect("serialize");
        assert!(
            !json.contains("destination"),
            "unset fields must not appear"
        );
        let back: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, finding);
    }
}
