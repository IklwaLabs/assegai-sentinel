//! Engine session state.
//!
//! The session is a small state machine rather than a boolean, because the UI needs to
//! distinguish "not started yet" from "stopped" from "failed", and because an error state must
//! carry its reason.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// What the engine is currently doing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    tag = "state",
    content = "detail",
    rename_all_fields = "camelCase"
)]
pub enum SessionState {
    /// No session has been started, or the last one was stopped cleanly.
    #[default]
    Idle,
    /// Interfaces are being discovered before a session starts.
    Preparing,
    /// Packets are being captured and analysed.
    Monitoring {
        /// Interface id being monitored.
        interface: String,
        /// Interface display name.
        interface_name: String,
    },
    /// A capture file is being analysed offline.
    Analyzing {
        /// File name, for display.
        file_name: String,
    },
    /// The session ended because of an error.
    Failed {
        /// Message already phrased for display.
        reason: String,
    },
}

impl SessionState {
    /// True when packets are being processed.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            SessionState::Monitoring { .. } | SessionState::Analyzing { .. }
        )
    }

    /// True when the session is neither running nor starting.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self, SessionState::Idle)
    }

    /// True when the session ended badly.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, SessionState::Failed { .. })
    }

    /// The interface id being monitored, when live.
    #[must_use]
    pub fn interface_id(&self) -> Option<&str> {
        match self {
            SessionState::Monitoring { interface, .. } => Some(interface),
            _ => None,
        }
    }

    /// Label for the status bar.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            SessionState::Idle => "Not monitoring".to_string(),
            SessionState::Preparing => "Preparing".to_string(),
            SessionState::Monitoring { interface_name, .. } => {
                format!("Monitoring {interface_name}")
            }
            SessionState::Analyzing { file_name } => format!("Analyzing {file_name}"),
            SessionState::Failed { reason } => format!("Stopped: {reason}"),
        }
    }

    /// Transitions to `Failed` with the given reason.
    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        SessionState::Failed {
            reason: reason.into(),
        }
    }
}

/// A compact summary of a session, used by the CLI and by the About panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    /// Frames seen.
    pub packets: u64,
    /// Bytes seen.
    pub bytes: u64,
    /// Flows created.
    pub flows_created: u64,
    /// Flows still tracked.
    pub flows_active: u64,
    /// Wall-clock duration in microseconds.
    pub duration_us: u64,
    /// Frames lost to backpressure or driver overflow.
    pub packets_lost: u64,
}

impl SessionSummary {
    /// True when the session lost any frames, so the numbers are known to be incomplete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.packets_lost == 0
    }

    /// Average throughput in bits per second over the session.
    #[must_use]
    pub fn average_bps(&self) -> f64 {
        let seconds = f64::from(self.duration_us.max(1_000_000) as u32) / 1_000_000.0;
        f64::from(self.bytes as u32) * 8.0 / seconds
    }
}

/// Chooses the addresses that represent this machine, for flow orientation.
///
/// Prefer IPv4: a LAN capture is almost always IPv4-first, and picking the wrong family would
/// make every flow look like it has no local side.
#[must_use]
pub fn prefer_local_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .find(|addr| addr.is_ipv4() && !addr.is_loopback())
        .or_else(|| addresses.iter().find(|addr| addr.is_ipv4()))
        .or_else(|| addresses.iter().find(|addr| !addr.is_loopback()))
        .copied()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn the_default_state_is_idle() {
        assert_eq!(SessionState::default(), SessionState::Idle);
        assert!(SessionState::default().is_idle());
        assert!(!SessionState::default().is_active());
    }

    #[test]
    fn active_states_report_themselves() {
        let live = SessionState::Monitoring {
            interface: "3".to_string(),
            interface_name: "Ethernet".to_string(),
        };
        assert!(live.is_active());
        assert!(!live.is_idle());
        assert_eq!(live.interface_id(), Some("3"));
        assert_eq!(live.label(), "Monitoring Ethernet");

        let offline = SessionState::Analyzing {
            file_name: "capture.pcap".to_string(),
        };
        assert!(offline.is_active());
        assert_eq!(
            offline.interface_id(),
            None,
            "an offline analysis has no interface"
        );
        assert_eq!(offline.label(), "Analyzing capture.pcap");
    }

    #[test]
    fn failure_carries_its_reason() {
        let failed = SessionState::failed("permission denied");
        assert!(failed.is_failed());
        assert!(!failed.is_active());
        assert!(failed.label().contains("permission denied"));
    }

    #[test]
    fn summaries_flag_incomplete_captures() {
        let complete = SessionSummary {
            packets: 1_000,
            bytes: 100_000,
            flows_created: 10,
            flows_active: 5,
            duration_us: 10_000_000,
            packets_lost: 0,
        };
        assert!(complete.is_complete());

        let lossy = SessionSummary {
            packets_lost: 12,
            ..complete
        };
        assert!(
            !lossy.is_complete(),
            "a lossy capture must not be presented as complete"
        );
    }

    #[test]
    fn throughput_uses_a_one_second_floor() {
        let burst = SessionSummary {
            packets: 1,
            bytes: 1_000_000,
            flows_created: 1,
            flows_active: 1,
            duration_us: 0,
            packets_lost: 0,
        };
        assert_eq!(
            burst.average_bps(),
            8_000_000.0,
            "1 MB in under a second reports as 8 Mbps"
        );

        let sustained = SessionSummary {
            duration_us: 2_000_000,
            ..burst
        };
        assert_eq!(
            sustained.average_bps(),
            4_000_000.0,
            "1 MB over 2 seconds is 4 Mbps"
        );
    }

    #[test]
    fn local_address_preference_picks_a_routable_ipv4() {
        let addresses = vec![
            "127.0.0.1".parse().expect("valid loopback"),
            "fe80::1".parse().expect("valid link local"),
            "192.168.1.10".parse().expect("valid v4"),
        ];
        assert_eq!(
            prefer_local_address(&addresses),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
    }

    #[test]
    fn local_address_preference_falls_back_when_only_loopback_exists() {
        let loopback = vec!["127.0.0.1".parse().expect("valid")];
        assert_eq!(prefer_local_address(&loopback), Some(loopback[0]));
    }

    #[test]
    fn local_address_preference_handles_no_addresses() {
        assert_eq!(prefer_local_address(&[]), None);
    }
}
