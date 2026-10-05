//! The engine's request/response boundary.
//!
//! The API layer (Tauri commands, the CLI, and later a remote sensor) is a thin client of this
//! boundary. It holds no analysis state, which is what keeps a future `sentinel-server` a
//! transport change rather than a rewrite.

use std::net::IpAddr;

use sentinel_common::config::AppConfig;
use sentinel_common::net::NetworkInterface;
use sentinel_platform::Capabilities;
use serde::{Deserialize, Serialize};

use crate::event::EngineSnapshot;
use crate::pipeline::PipelineStats;
use crate::session::{SessionState, SessionSummary};

/// Identifies the local machine, for flow orientation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestContext {
    /// Addresses assigned to the monitored interfaces.
    pub local_addresses: Vec<IpAddr>,
    /// Highest local address chosen for orientation.
    pub primary_address: Option<IpAddr>,
}

impl RequestContext {
    /// Builds a context from interface addresses, preferring routable IPv4.
    #[must_use]
    pub fn from_interfaces(interfaces: &[NetworkInterface]) -> Self {
        let local_addresses: Vec<IpAddr> = interfaces
            .iter()
            .flat_map(|iface| iface.addresses.iter().map(|a| a.addr))
            .collect();
        Self {
            primary_address: crate::session::prefer_local_address(&local_addresses),
            local_addresses,
        }
    }

    /// Builds an empty context, used before interfaces are known.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// A request to the engine.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineRequest {
    /// List capturable interfaces.
    ListInterfaces,
    /// Report what capture is possible in this process.
    Capabilities,
    /// Report the current state without starting anything.
    Status,
    /// Start monitoring a named interface.
    Start {
        /// Interface id, as returned by `ListInterfaces`.
        interface_id: String,
    },
    /// Stop the current session.
    Stop,
    /// Analyse a capture file offline.
    Analyze {
        /// Path to the capture file.
        path: String,
    },
    /// Fetch a full snapshot now, rather than waiting for the next heartbeat.
    Snapshot,
    /// Read the effective configuration.
    GetConfig,
    /// Replace the effective configuration.
    SetConfig {
        /// New configuration. Validated before it is applied.
        config: AppConfig,
    },
}

/// A response to an [`EngineRequest`].
///
/// A single enum rather than a channel per request type: the set is small, it keeps the
/// request/response pair in one place, and adding a variant is a compile-time change in every
/// client rather than a silent behaviour change.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// Available interfaces.
    Interfaces(Vec<NetworkInterface>),
    /// Platform capabilities.
    Capabilities(Box<Capabilities>),
    /// Current state and a short summary.
    Status {
        /// Session state.
        state: SessionState,
        /// Counters for the running or last session.
        summary: SessionSummary,
    },
    /// A session started.
    Started {
        /// Interface or file being analysed.
        state: SessionState,
    },
    /// A session stopped.
    Stopped,
    /// A full snapshot.
    Snapshot(Box<EngineSnapshot>),
    /// The effective configuration.
    Config(Box<AppConfig>),
    /// The request completed with nothing to return.
    Acknowledged,
}

/// A status response without a session, for callers that only need the state.
#[must_use]
pub fn idle_status() -> Response {
    Response::Status {
        state: SessionState::Idle,
        summary: SessionSummary {
            packets: 0,
            bytes: 0,
            flows_created: 0,
            flows_active: 0,
            duration_us: 0,
            packets_lost: 0,
        },
    }
}

/// Pipeline statistics for diagnostics.
#[must_use]
pub fn stats_only(stats: PipelineStats) -> Response {
    Response::Snapshot(Box::new(EngineSnapshot {
        state: SessionState::Idle,
        interface: None,
        total_upload_bytes: 0,
        total_download_bytes: 0,
        total_packets: 0,
        first_seen_us: 0,
        last_seen_us: 0,
        upload_bps: 0.0,
        download_bps: 0.0,
        traffic: Vec::new(),
        connections: Vec::new(),
        flows_active: 0,
        stats,
        metrics: sentinel_common::metrics::MetricsSnapshot::default(),
        config: AppConfig::default(),
    }))
}

#[cfg(test)]
mod tests {
    use sentinel_common::net::InterfaceAddress;

    use super::*;

    fn interfaces() -> Vec<NetworkInterface> {
        let mut ethernet = NetworkInterface::new("3", "Ethernet");
        ethernet.addresses.push(InterfaceAddress::new(
            "192.168.1.10".parse().expect("valid"),
            24,
        ));
        ethernet
            .addresses
            .push(InterfaceAddress::new("fe80::1".parse().expect("valid"), 64));

        let mut wifi = NetworkInterface::new("9", "Wi-Fi");
        wifi.addresses.push(InterfaceAddress::new(
            "10.0.0.5".parse().expect("valid"),
            24,
        ));
        vec![ethernet, wifi]
    }

    #[test]
    fn a_context_prefers_routable_ipv4() {
        let context = RequestContext::from_interfaces(&interfaces());
        assert_eq!(
            context.primary_address,
            Some("192.168.1.10".parse().expect("valid"))
        );
        assert_eq!(
            context.local_addresses.len(),
            3,
            "every interface address is collected"
        );
    }

    #[test]
    fn an_empty_context_is_safe() {
        let context = RequestContext::empty();
        assert!(context.primary_address.is_none());
        assert!(context.local_addresses.is_empty());
    }

    #[test]
    fn a_context_with_no_interfaces_is_safe() {
        let context = RequestContext::from_interfaces(&[]);
        assert!(context.primary_address.is_none());
    }

    #[test]
    fn idle_status_reports_a_zeroed_session() {
        let Response::Status { state, summary } = idle_status() else {
            panic!("expected a status response")
        };
        assert_eq!(state, SessionState::Idle);
        assert_eq!(summary.packets, 0);
        assert!(summary.is_complete());
    }

    #[test]
    fn requests_are_comparable() {
        // Requests are matched on by the engine, so equality is part of the contract.
        assert_eq!(EngineRequest::Stop, EngineRequest::Stop);
        assert_eq!(
            EngineRequest::Start {
                interface_id: "3".to_string()
            },
            EngineRequest::Start {
                interface_id: "3".to_string()
            }
        );
        assert_ne!(
            EngineRequest::Start {
                interface_id: "3".to_string()
            },
            EngineRequest::Start {
                interface_id: "9".to_string()
            }
        );
    }

    #[test]
    fn responses_are_comparable() {
        assert_eq!(Response::Stopped, Response::Stopped);
        assert_eq!(Response::Acknowledged, Response::Acknowledged);
        assert_ne!(Response::Stopped, Response::Acknowledged);
    }
}
