//! Flow tracking and traffic aggregation.
//!
//! Flows are the primary unit Sentinel shows to users, so this crate owns the two things
//! that turn a stream of packets into something a person can reason about:
//!
//! - [`FlowTable`]: bidirectional flow keying with counters, state and idle eviction.
//! - [`TrafficAggregator`]: coarse time-bucketed totals for charts and the overview.
//!
//! Neither this crate nor its callers persist anything. Storage receives finished flows;
//! detection receives flow events. That keeps analysis testable without a database.
//!
//! [`privacy`] is the one exception to "owns two things": redaction is a property of how an
//! endpoint is *written out*, which is the same knowledge as keying, and putting it in the
//! crate that defines [`Endpoint`] keeps it testable without a database or a config file.

pub mod aggregate;
pub mod flow;
pub mod key;
pub mod privacy;
pub mod table;

pub use aggregate::{ProtocolTotals, TrafficAggregator, TrafficSample, TrafficSummary};
pub use flow::{Flow, FlowState, FlowUpdate};
pub use key::FlowKey;
pub use privacy::{Redaction, Redactor, is_private_address};
pub use table::FlowTable;

/// A flow engine failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    /// The tracked-flow cap was reached and the table cannot accept more flows.
    #[error("flow table is full ({0} flows tracked)")]
    TableFull(usize),
}

impl sentinel_common::error::UserFacing for FlowError {
    fn user_message(&self) -> sentinel_common::error::UserMessage {
        use sentinel_common::error::UserMessage;
        match self {
            FlowError::TableFull(limit) => UserMessage::new(
                "Sentinel is tracking the maximum number of connections",
                format!("The limit of {limit} active connections was reached, so the oldest idle connections are being retired to keep the view responsive."),
            )
            .with_hint("This is expected on very busy networks; active traffic is still shown.")
            .with_hint("Reduce noise by excluding local or virtual adapters in Settings."),
        }
    }
}
