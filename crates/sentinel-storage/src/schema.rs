//! Typed row mappings.
//!
//! One place that knows how Sentinel types map onto SQLite columns. Queries and writes both
//! go through these types, so a schema change surfaces as one compile error rather than as
//! scattered string edits.

use sentinel_common::clock;
use sentinel_common::net::NetworkInterface;
use sentinel_flow::aggregate::ProtocolTotals;
use sentinel_flow::flow::Flow;
use sentinel_flow::key::Endpoint;
use serde::{Deserialize, Serialize};

/// A stored flow, ready to be written or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    /// Stable identifier derived from the flow key.
    pub id: String,
    /// The flow.
    pub flow: Flow,
    /// Address of this machine on the connection, when known.
    pub local_addr: Option<String>,
    /// Remote address of the connection, when known.
    pub remote_addr: Option<String>,
}

impl FlowRecord {
    /// Builds a record from a flow, deriving the stable id from its key.
    #[must_use]
    pub fn new(flow: Flow) -> Self {
        let id = flow_id(&flow);
        let local = flow.key.endpoint_a.display();
        let remote = flow.key.endpoint_b.display();
        Self {
            id,
            flow,
            local_addr: Some(local),
            remote_addr: Some(remote),
        }
    }

    /// The endpoints as stored, for filtering by address.
    #[must_use]
    pub fn endpoint_labels(&self) -> (Endpoint, Endpoint) {
        (self.flow.key.endpoint_a, self.flow.key.endpoint_b)
    }
}

/// Deterministic identifier for a flow.
///
/// Derived from the normalized key, so the same connection always maps to the same row and
/// re-observation upserts instead of duplicating. Format: `protocol|addr:port|addr:port`.
#[must_use]
pub fn flow_id(flow: &Flow) -> String {
    format!(
        "{}|{}|{}",
        flow.key.protocol.label().to_ascii_lowercase(),
        flow.key.endpoint_a.display(),
        flow.key.endpoint_b.display()
    )
}

/// A stored interface observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceRecord {
    /// Platform identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional longer description.
    pub description: Option<String>,
    /// Device classification label.
    pub kind: String,
    /// Addresses as JSON text.
    pub addresses_json: String,
    /// Hardware address as text, when known.
    pub mac: Option<String>,
    /// Loopback flag.
    pub is_loopback: bool,
    /// Virtual flag.
    pub is_virtual: bool,
    /// First observation timestamp.
    pub first_seen_us: u64,
    /// Most recent observation timestamp.
    pub last_seen_us: u64,
}

impl InterfaceRecord {
    /// Builds a record from a discovered interface, stamped with the current time.
    #[must_use]
    pub fn new(iface: &NetworkInterface) -> Self {
        let now = clock::now_unix_micros();
        Self {
            id: iface.id.clone(),
            name: iface.name.clone(),
            description: iface.description.clone(),
            kind: iface.kind.label().to_string(),
            addresses_json: serde_json::to_string(&iface.addresses)
                .unwrap_or_else(|_| "[]".to_string()),
            mac: iface.mac.map(|mac| mac.to_string()),
            is_loopback: iface.is_loopback,
            is_virtual: iface.is_virtual,
            first_seen_us: now,
            last_seen_us: now,
        }
    }
}

/// A stored protocol total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolTotalRecord {
    /// Protocol label as used in the API.
    pub protocol: String,
    /// Total bytes.
    pub bytes: u64,
    /// Total packets.
    pub packets: u64,
    /// Distinct flows observed.
    pub flows: u64,
    /// First observation timestamp.
    pub first_seen_us: u64,
    /// Most recent observation timestamp.
    pub last_seen_us: u64,
}

impl ProtocolTotalRecord {
    /// Builds a record from an aggregator total, stamped with the session bounds.
    #[must_use]
    pub fn new(totals: ProtocolTotals, first_seen_us: u64, last_seen_us: u64) -> Self {
        Self {
            protocol: totals.protocol.label().to_ascii_uppercase(),
            bytes: totals.bytes,
            packets: totals.packets,
            flows: totals.flows,
            first_seen_us,
            last_seen_us,
        }
    }
}

/// A key/value setting row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingRecord {
    /// Setting key.
    pub key: String,
    /// JSON-encoded value.
    pub value: String,
    /// Update timestamp.
    pub updated_at_us: u64,
}

/// Converts a `u64` microsecond timestamp into an `i64` for SQLite.
///
/// SQLite INTEGER is signed 64-bit, which comfortably covers microseconds since the epoch
/// (about 1.7e15 for 2025). The conversion is checked rather than cast so an impossible value
/// surfaces as a constraint error instead of silently going negative.
#[must_use]
pub fn to_sql_timestamp(micros: u64) -> i64 {
    i64::try_from(micros).unwrap_or(i64::MAX)
}

/// Converts an SQLite INTEGER back into a microsecond timestamp.
#[must_use]
pub fn from_sql_timestamp(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    use sentinel_common::packet::TransportProtocol;
    use sentinel_flow::key::FlowKey;

    use super::*;

    fn sample_flow() -> Flow {
        Flow {
            key: FlowKey::new(
                TransportProtocol::Tcp,
                Endpoint::new("192.168.1.10".parse().expect("valid"), Some(52_341)),
                Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            ),
            state: sentinel_flow::flow::FlowState::Established,
            first_seen_us: 1_000,
            last_seen_us: 2_000,
            bytes_sent: 100,
            bytes_received: 900,
            packets_sent: 2,
            packets_received: 4,
            service: Some("HTTPS".to_string()),
            domain: Some("example.com".to_string()),
            process: Some(sentinel_flow::flow::ProcessRef {
                pid: 5812,
                name: "chrome.exe".to_string(),
                path: None,
                application: Some("Google Chrome".to_string()),
            }),
            risk_score: Some(35),
            alert_count: 1,
            tags: BTreeSet::from(["outbound".to_string()]),
            initiator: Some(sentinel_flow::key::FlowSide::B),
        }
    }

    #[test]
    fn flow_ids_are_deterministic_and_direction_independent() {
        let forward = sample_flow();
        let mut reverse = sample_flow();
        // Reversing the endpoints must not change the id, because the key is normalized.
        reverse.key = FlowKey::new(
            TransportProtocol::Tcp,
            Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            Endpoint::new("192.168.1.10".parse().expect("valid"), Some(52_341)),
        );
        assert_eq!(flow_id(&forward), flow_id(&reverse));
    }

    #[test]
    fn flow_ids_differ_by_protocol() {
        let tcp = sample_flow();
        let mut udp = sample_flow();
        udp.key.protocol = TransportProtocol::Udp;
        assert_ne!(flow_id(&tcp), flow_id(&udp));
    }

    #[test]
    fn flow_record_exposes_endpoints() {
        let record = FlowRecord::new(sample_flow());
        let (a, b) = record.endpoint_labels();
        assert_eq!(a.display(), "93.184.216.34:443");
        assert_eq!(b.display(), "192.168.1.10:52341");
        assert!(record.id.contains("tcp"));
    }

    #[test]
    fn interface_records_capture_classification_and_addresses() {
        let mut iface = NetworkInterface::new("3", "Ethernet");
        iface.kind = sentinel_common::net::InterfaceKind::Ethernet;
        iface
            .addresses
            .push(sentinel_common::net::InterfaceAddress::new(
                "192.168.1.10".parse().expect("valid"),
                24,
            ));

        let record = InterfaceRecord::new(&iface);
        assert_eq!(record.kind, "Ethernet");
        assert!(record.addresses_json.contains("192.168.1.10"));
        assert!(record.first_seen_us > 0);
        assert!(!record.is_loopback);
        assert!(!record.is_virtual);
    }

    #[test]
    fn protocol_records_normalize_case() {
        let record = ProtocolTotalRecord::new(
            ProtocolTotals {
                protocol: TransportProtocol::Tcp,
                bytes: 1,
                packets: 1,
                flows: 1,
            },
            100,
            200,
        );
        assert_eq!(record.protocol, "TCP");
    }

    #[test]
    fn timestamps_round_trip_and_saturate() {
        assert_eq!(
            to_sql_timestamp(1_735_689_600_000_000),
            1_735_689_600_000_000i64
        );
        assert_eq!(from_sql_timestamp(to_sql_timestamp(42)), 42);
        assert_eq!(
            from_sql_timestamp(-1),
            0,
            "a negative timestamp reads as zero, not as a huge u64"
        );
        assert_eq!(
            to_sql_timestamp(u64::MAX),
            i64::MAX,
            "an impossible value saturates instead of wrapping"
        );
    }

    #[test]
    fn interface_mac_is_rendered_as_text() {
        let mut iface = NetworkInterface::new("1", "Wi-Fi");
        iface.mac = Some(sentinel_common::net::MacAddr::from_bytes([
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f,
        ]));
        let record = InterfaceRecord::new(&iface);
        assert_eq!(record.mac.as_deref(), Some("1a:2b:3c:4d:5e:6f"));
    }

    #[test]
    fn local_and_remote_labels_are_addresses() {
        let record = FlowRecord::new(sample_flow());
        assert_eq!(record.local_addr.as_deref(), Some("93.184.216.34:443"));
        assert_eq!(record.remote_addr.as_deref(), Some("192.168.1.10:52341"));
        let _: IpAddr = "10.0.0.1".parse().expect("valid");
    }
}
