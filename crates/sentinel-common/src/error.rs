//! User-facing error contract.
//!
//! Library crates return typed errors. Anything that a human may see converts those
//! typed errors into a [`UserMessage`] through [`UserFacing`], so the UI can show
//! "what happened, why, what to do" while the technical detail stays available behind a
//! disclosure.

use std::fmt;

/// An actionable message intended for display.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserMessage {
    /// Short headline, e.g. "Packet capture permission is missing".
    pub title: String,
    /// One or two sentences explaining the situation in plain language.
    pub summary: String,
    /// Concrete next steps, most useful first.
    #[serde(default)]
    pub hint: Vec<String>,
    /// Technical detail for support or bug reports. Never required.
    #[serde(default)]
    pub details: Option<String>,
}

impl UserMessage {
    /// Creates a message with a title and summary and no hints.
    pub fn new(title: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            summary: summary.into(),
            hint: Vec::new(),
            details: None,
        }
    }

    /// Adds one or more hints.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint.push(hint.into());
        self
    }

    /// Attaches technical detail.
    #[must_use]
    pub fn with_details(mut self, details: impl fmt::Display) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Renders the message as a single block of text (used by the CLI).
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

/// Conversion of a typed error into an actionable message.
///
/// Implementations should be exhaustive over the error variants they own so a new
/// variant forces a decision about how it is presented.
pub trait UserFacing {
    /// Produces the user-facing message for this error.
    fn user_message(&self) -> UserMessage;
}

impl UserFacing for std::io::Error {
    fn user_message(&self) -> UserMessage {
        UserMessage::new("A local system operation failed", self.to_string())
            .with_hint("Check that Sentinel still has access to its data directory.")
            .with_hint("Retry the action; if it keeps failing, export logs from Settings.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_includes_all_sections() {
        let msg = UserMessage::new("Title", "Summary")
            .with_hint("Do this")
            .with_details("io error: broken pipe");
        let text = msg.to_plain_text();
        assert!(text.contains("Title"));
        assert!(text.contains("Summary"));
        assert!(text.contains("Do this"));
        assert!(text.contains("broken pipe"));
    }
}
