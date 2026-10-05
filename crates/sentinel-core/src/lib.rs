//! Engine orchestration for Iklwa Sentinel.
//!
//! This crate is where the pipeline in `ARCHITECTURE.md` becomes running code:
//!
//! ```text
//! CaptureSource -> bounded queue -> decoder -> flow table -> aggregator -> storage -> events
//! ```
//!
//! # Concurrency
//!
//! One **engine task** owns all mutable analysis state: the flow table, the traffic
//! aggregator, the storage writer handle and the event broadcaster. Callers send
//! [`EngineRequest`]s and receive replies over a oneshot channel. There is exactly one writer
//! of the flow table, which is why no locks appear in the hot path.
//!
//! Capture runs on its own OS thread inside [`sentinel_capture`], because `libpcap` reads block.
//! It publishes into a bounded queue, so a slow engine applies backpressure by dropping frames
//! (counted, never silent) rather than stalling the driver.
//!
//! # Boundaries
//!
//! The engine performs no analysis of its own. Detection, threat intelligence and risk scoring
//! are separate crates added by later milestones and plugged in as a stage after the flow
//! update. Keeping that seam visible now is what stops the engine from becoming a god object.

pub mod engine;
pub mod error;
pub mod event;
pub mod pipeline;
pub mod request;
pub mod session;

pub use engine::{Engine, EngineHandle, EngineOptions};
pub use error::{CoreError, Result};
pub use event::{EngineEvent, EventKind};
pub use pipeline::{PipelineConfig, PipelineCounters, PipelineStats};
pub use request::{EngineRequest, RequestContext, Response};
pub use session::{SessionState, SessionSummary};
