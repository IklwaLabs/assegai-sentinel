//! The error shape every frontend sees.
//!
//! One error type on the wire, always carrying both the human-facing message and the technical
//! detail. A frontend shows `title`, `summary` and `hint` in the interface and puts `details`
//! behind a disclosure, so no raw driver or database string is ever the only thing a user sees.

use sentinel_common::error::{UserFacing, UserMessage};
use serde::{Deserialize, Serialize};

/// Result alias for API operations.
pub type ApiResult<T> = Result<T, ApiError>;

/// An error returned to a frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Stable identifier for the failure category, for programmatic handling.
    pub kind: ApiErrorKind,
    /// What happened, in one line.
    pub title: String,
    /// Why it happened, in plain language.
    pub summary: String,
    /// Concrete next steps.
    #[serde(default)]
    pub hint: Vec<String>,
    /// Technical detail, for a support bundle. Optional.
    #[serde(default)]
    pub details: Option<String>,
}

/// Failure categories a frontend can branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApiErrorKind {
    /// The operating system refused the operation, usually a missing privilege.
    Permission,
    /// A capture driver is missing or unusable.
    Driver,
    /// The requested network interface is not available.
    Interface,
    /// A configuration value was rejected.
    Configuration,
    /// Local storage failed.
    Storage,
    /// The engine is not in a state where the request makes sense.
    InvalidState,
    /// The engine stopped or stopped answering.
    Engine,
    /// The feature does not exist on this platform or in this build.
    Unsupported,
}

impl ApiError {
    /// Builds an error from any Sentinel error that can describe itself.
    #[must_use]
    pub fn from_error(err: &impl UserFacing, kind: ApiErrorKind) -> Self {
        let message: UserMessage = err.user_message();
        Self {
            kind,
            title: message.title,
            summary: message.summary,
            hint: message.hint,
            details: message.details,
        }
    }

    /// Builds an error from a message that is already user-facing.
    #[must_use]
    pub fn from_message(message: UserMessage, kind: ApiErrorKind) -> Self {
        Self {
            kind,
            title: message.title,
            summary: message.summary,
            hint: message.hint,
            details: message.details,
        }
    }

    /// Renders the error for a terminal.
    #[must_use]
    pub fn to_plain_text(&self) -> String {
        let mut out = format!("{}\n\n{}", self.title, self.summary);
        if !self.hint.is_empty() {
            out.push_str("\n\nWhat to do:");
            for hint in &self.hint {
                out.push_str("\n  - ");
                out.push_str(hint);
            }
        }
        if let Some(details) = &self.details {
            out.push_str("\n\nDetails:\n  ");
            out.push_str(details);
        }
        out
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_plain_text())
    }
}

impl std::error::Error for ApiError {}

impl From<sentinel_core::CoreError> for ApiError {
    fn from(err: sentinel_core::CoreError) -> Self {
        let kind = classify(&err);
        Self::from_error(&err, kind)
    }
}

/// Maps an engine error to the category a frontend branches on.
///
/// The distinctions matter to the interface: a permission failure is worth offering an
/// elevation hint for, an invalid state is not, and a missing driver is neither.
fn classify(err: &sentinel_core::CoreError) -> ApiErrorKind {
    use sentinel_capture::CaptureError;
    use sentinel_core::CoreError;

    match err {
        CoreError::Capture(CaptureError::PermissionDenied { .. }) => ApiErrorKind::Permission,
        CoreError::Capture(_) => ApiErrorKind::Driver,
        CoreError::Platform(_) => ApiErrorKind::Driver,
        CoreError::Storage(_) => ApiErrorKind::Storage,
        CoreError::Config(_) => ApiErrorKind::Configuration,
        CoreError::UnknownInterface(_) => ApiErrorKind::Interface,
        CoreError::AlreadyRunning(_) | CoreError::NotRunning => ApiErrorKind::InvalidState,
        CoreError::EngineStopped(_) | CoreError::RequestFailed(_) => ApiErrorKind::Engine,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_error_keeps_its_guidance() {
        let err = sentinel_core::CoreError::NotRunning;
        let api: ApiError = err.into();

        assert_eq!(api.kind, ApiErrorKind::InvalidState);
        assert!(!api.title.is_empty());
        assert!(
            api.hint
                .iter()
                .any(|hint| hint.contains("start monitoring"))
        );
    }

    #[test]
    fn permission_failures_are_classified_for_the_ui() {
        use sentinel_capture::CaptureError;
        let err = sentinel_core::CoreError::Capture(CaptureError::PermissionDenied {
            details: "denied".to_string(),
        });
        let api: ApiError = err.into();
        assert_eq!(
            api.kind,
            ApiErrorKind::Permission,
            "the ui branches on this to offer elevation help"
        );
    }

    #[test]
    fn unknown_interfaces_are_classified_separately_from_permissions() {
        let err = sentinel_core::CoreError::UnknownInterface("9".to_string());
        let api: ApiError = err.into();
        assert_eq!(api.kind, ApiErrorKind::Interface);
    }

    #[test]
    fn errors_serialize_with_a_stable_shape() {
        let api = ApiError {
            kind: ApiErrorKind::Storage,
            title: "Could not write".to_string(),
            summary: "The database rejected a write.".to_string(),
            hint: vec!["Check disk space.".to_string()],
            details: Some("disk I/O error".to_string()),
        };
        let json = serde_json::to_value(&api).expect("serialize");
        assert_eq!(json["kind"], serde_json::json!("storage"));
        assert_eq!(json["title"], serde_json::json!("Could not write"));
        assert_eq!(json["hint"][0], serde_json::json!("Check disk space."));

        let parsed: ApiError = serde_json::from_value(json).expect("deserialize");
        assert_eq!(parsed, api);
    }

    #[test]
    fn details_are_optional_on_the_wire() {
        let json = serde_json::json!({
            "kind": "engine",
            "title": "Stopped",
            "summary": "The engine stopped.",
        });
        let parsed: ApiError = serde_json::from_value(json).expect("deserialize without details");
        assert!(parsed.details.is_none());
        assert!(parsed.hint.is_empty());
    }

    #[test]
    fn plain_text_includes_every_section() {
        let api = ApiError {
            kind: ApiErrorKind::Driver,
            title: "Driver missing".to_string(),
            summary: "Npcap is not installed.".to_string(),
            hint: vec!["Install Npcap.".to_string()],
            details: Some("wpcap.dll not found".to_string()),
        };
        let text = api.to_plain_text();
        assert!(text.contains("Driver missing"));
        assert!(text.contains("What to do"));
        assert!(text.contains("Install Npcap."));
        assert!(text.contains("wpcap.dll not found"));
    }
}
