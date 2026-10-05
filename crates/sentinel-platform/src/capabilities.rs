//! What this process can do right now, on this operating system.
//!
//! The desktop UI shows a plain-language capability summary before the user starts
//! monitoring, so failures happen at the right moment instead of as a mid-session error.

use serde::{Deserialize, Serialize};

/// Packet capture mechanism available on this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureBackend {
    /// Npcap on Windows.
    Npcap,
    /// libpcap on Linux.
    Libpcap,
    /// libpcap over BPF on macOS.
    Bpf,
    /// `VpnService` TUN tunnel on Android, bridged from Kotlin.
    AndroidTun,
    /// No capture backend in this build.
    Unsupported,
}

impl CaptureBackend {
    /// Human-readable backend name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CaptureBackend::Npcap => "Npcap",
            CaptureBackend::Libpcap => "libpcap",
            CaptureBackend::Bpf => "BPF (libpcap)",
            CaptureBackend::AndroidTun => "Android VPN tunnel",
            CaptureBackend::Unsupported => "Unavailable",
        }
    }

    /// Short technical description for diagnostics output.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            CaptureBackend::Npcap => "Windows: Npcap (WinPcap-compatible API) over NDIS",
            CaptureBackend::Libpcap => "Linux: libpcap over AF_PACKET",
            CaptureBackend::Bpf => "macOS: libpcap over /dev/bpf",
            CaptureBackend::AndroidTun => "Android: VpnService TUN fd bridged through JNI",
            CaptureBackend::Unsupported => "no capture driver present in this build",
        }
    }
}

/// Whether the current process is elevated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivilegeState {
    /// Process runs with administrative rights.
    Elevated,
    /// Process runs as a normal user; capture may still work depending on driver setup.
    NotElevated,
    /// Privilege state could not be determined.
    Unknown,
}

impl PrivilegeState {
    /// Label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            PrivilegeState::Elevated => "Elevated",
            PrivilegeState::NotElevated => "Standard user",
            PrivilegeState::Unknown => "Unknown",
        }
    }
}

/// Platform capability summary for diagnostics and first-run UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Capture backend in use.
    pub backend: CaptureBackend,
    /// Whether the capture library loaded successfully.
    pub library_present: bool,
    /// Whether capture requires an elevated process on this platform.
    pub requires_elevation: bool,
    /// Current privilege state.
    pub privilege: PrivilegeState,
    /// Whether loopback traffic can be captured.
    pub loopback_supported: bool,
    /// Largest snapshot length the backend accepts.
    pub max_snaplen: u32,
    /// Additional facts worth surfacing (driver versions, group membership, ...).
    pub notes: Vec<String>,
}

impl Capabilities {
    /// True when capture is possible in principle in this build.
    #[must_use]
    pub const fn capture_available(&self) -> bool {
        match self.backend {
            CaptureBackend::Unsupported => false,
            _ => self.library_present,
        }
    }

    /// True when capture is possible without changing how the process was started.
    #[must_use]
    pub fn capture_available_now(&self) -> bool {
        self.capture_available()
            && (!self.requires_elevation || self.privilege == PrivilegeState::Elevated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        backend: CaptureBackend,
        present: bool,
        requires_elevation: bool,
        privilege: PrivilegeState,
    ) -> Capabilities {
        Capabilities {
            backend,
            library_present: present,
            requires_elevation,
            privilege,
            loopback_supported: false,
            max_snaplen: 262_144,
            notes: Vec::new(),
        }
    }

    #[test]
    fn availability_accounts_for_driver_and_privileges() {
        let ready = sample(CaptureBackend::Npcap, true, true, PrivilegeState::Elevated);
        assert!(ready.capture_available());
        assert!(ready.capture_available_now());

        let standard_user = sample(
            CaptureBackend::Npcap,
            true,
            true,
            PrivilegeState::NotElevated,
        );
        assert!(standard_user.capture_available());
        assert!(!standard_user.capture_available_now());

        let no_driver = sample(CaptureBackend::Npcap, false, true, PrivilegeState::Elevated);
        assert!(!no_driver.capture_available());

        let unsupported = sample(
            CaptureBackend::Unsupported,
            false,
            false,
            PrivilegeState::Unknown,
        );
        assert!(!unsupported.capture_available());
        assert!(!unsupported.capture_available_now());
    }

    #[test]
    fn backends_describe_themselves() {
        assert!(CaptureBackend::Npcap.detail().contains("Npcap"));
        assert!(CaptureBackend::AndroidTun.detail().contains("JNI"));
        assert_eq!(CaptureBackend::Unsupported.label(), "Unavailable");
        assert_eq!(PrivilegeState::NotElevated.label(), "Standard user");
    }
}
