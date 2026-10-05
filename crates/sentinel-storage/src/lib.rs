//! Local persistence for Iklwa Sentinel.
//!
//! Scope and shape:
//!
//! - **SQLite in WAL mode, one writer thread.** Writes are batched inside transactions.
//!   A local desktop database has exactly one writer, so an asynchronous pool would add
//!   complexity without adding throughput.
//! - **Aggregates, not packets.** Flows are stored when they finish or on a flush cadence,
//!   and traffic samples are stored per second. Raw packet storage is rejected by design.
//! - **Migrations from the first commit.** `migrations/` holds plain SQL applied in order
//!   and tracked in `schema_migrations`, so a database can always be brought to the shape the
//!   current binary expects.
//! - **Retention is enforced by code.** Configurable retention with a cleanup job, not by
//!   hoping the user deletes the database.
//!
//! Every statement is static and bound through [`rusqlite`] parameters. No SQL string is ever
//! built from user or network input.

pub mod db;
pub mod error;
pub mod migrations;
pub mod retention;
pub mod schema;
pub mod statements;
pub mod writer;

pub use db::{Database, DatabaseOptions};
pub use error::{Result, StorageError};
pub use retention::{CleanupReport, RetentionJob};
pub use schema::{FlowRecord, InterfaceRecord, ProtocolTotalRecord};
pub use writer::{StorageWriter, WriteBatch, WriteItem, WriterStats};
