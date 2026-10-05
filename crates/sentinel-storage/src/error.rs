//! Storage errors with actionable messages.

use sentinel_common::error::{UserFacing, UserMessage};

/// Result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

/// A persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The database file or its directory could not be accessed.
    #[error("could not access the Sentinel database: {0}")]
    Access(String),

    /// SQLite reported an error.
    #[error("database error: {0}")]
    Sqlite(String),

    /// A row could not be read back or converted.
    #[error("stored data could not be decoded: {0}")]
    Corrupt(String),

    /// The database schema is newer than this build understands.
    #[error("database schema version {found} is newer than this build supports ({supported})")]
    SchemaTooNew {
        /// Version found in the database.
        found: u32,
        /// Highest version this build supports.
        supported: u32,
    },

    /// A migration failed to apply.
    #[error("migration {name} failed: {details}")]
    Migration {
        /// Migration name.
        name: String,
        /// Underlying detail.
        details: String,
    },

    /// A write was rejected because it would violate a schema constraint.
    #[error("{context} violates a database constraint: {details}")]
    Constraint {
        /// What was being written.
        context: &'static str,
        /// Underlying detail.
        details: String,
    },
}

impl StorageError {
    /// True when the failure is a transient lock contention, where retrying is worthwhile.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        let StorageError::Sqlite(details) = self else {
            return false;
        };
        details.contains("database is locked") || details.contains("database table is locked")
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        use rusqlite::Error;
        use rusqlite::ffi::ErrorCode;

        match err {
            Error::QueryReturnedNoRows => {
                StorageError::Corrupt("expected a row, found none".to_string())
            }
            // A constraint failure arrives as SqliteFailure with a constraint error code.
            // Matching on the code rather than the message keeps this classification stable.
            Error::SqliteFailure(failure, details)
                if failure.code == ErrorCode::ConstraintViolation =>
            {
                StorageError::Constraint {
                    context: "write",
                    details: details.unwrap_or_else(|| failure.to_string()),
                }
            }
            Error::SqliteFailure(failure, Some(details)) => {
                StorageError::Sqlite(format!("{failure}: {details}"))
            }
            Error::SqliteFailure(failure, None) => StorageError::Sqlite(failure.to_string()),
            other => StorageError::Sqlite(other.to_string()),
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Access(err.to_string())
    }
}

impl UserFacing for StorageError {
    fn user_message(&self) -> UserMessage {
        match self {
            StorageError::Access(details) => UserMessage::new(
                "Sentinel could not open its local database",
                "The data directory is missing, read-only, or locked by another process.",
            )
            .with_hint("Check available disk space and folder permissions.")
            .with_hint("If another Sentinel window is open, close it and try again.")
            .with_hint("The data directory is shown in Settings.")
            .with_details(details.clone()),
            StorageError::Sqlite(details) => UserMessage::new(
                "Sentinel could not write to its local database",
                "A database operation failed. Monitoring continues and unsaved data is kept in memory until it can be written.",
            )
            .with_hint("If this repeats, export your logs from Settings and report the details.")
            .with_details(details.clone()),
            StorageError::Corrupt(details) => UserMessage::new(
                "Sentinel found unreadable stored data",
                "A record in the local database could not be decoded and was skipped.",
            )
            .with_hint("Recent live data is unaffected.")
            .with_details(details.clone()),
            StorageError::SchemaTooNew { found, supported } => UserMessage::new(
                "This database was written by a newer version of Sentinel",
                format!("The database schema is version {found}, but this build supports up to {supported}."),
            )
            .with_hint("Update Sentinel to the version that created this database.")
            .with_hint("Export your data first if you intend to downgrade.")
            .with_details(format!("found: {found}, supported: {supported}")),
            StorageError::Migration { name, details } => UserMessage::new(
                "Sentinel could not update its database",
                format!("Applying the migration '{name}' failed, so the database was left unchanged."),
            )
            .with_hint("Back up the data directory before retrying.")
            .with_details(details.clone()),
            StorageError::Constraint { context, details } => UserMessage::new(
                "Sentinel could not store a record",
                format!("A {context} did not match the database schema."),
            )
            .with_details(details.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_contention_is_marked_retryable() {
        let locked = StorageError::Sqlite("database is locked".to_string());
        assert!(locked.is_retryable());

        let other = StorageError::Sqlite("disk I/O error".to_string());
        assert!(!other.is_retryable());

        let access = StorageError::Access("permission denied".to_string());
        assert!(!access.is_retryable());
    }

    #[test]
    fn schema_too_new_names_both_versions() {
        let err = StorageError::SchemaTooNew {
            found: 4,
            supported: 2,
        };
        assert!(err.to_string().contains('4'));
        assert!(err.to_string().contains('2'));
        assert!(
            UserFacing::user_message(&err)
                .title
                .contains("newer version")
        );
    }

    #[test]
    fn every_error_produces_a_titled_message() {
        let errors = [
            StorageError::Access("x".into()),
            StorageError::Sqlite("x".into()),
            StorageError::Corrupt("x".into()),
            StorageError::SchemaTooNew {
                found: 2,
                supported: 1,
            },
            StorageError::Migration {
                name: "0002".into(),
                details: "x".into(),
            },
            StorageError::Constraint {
                context: "flow record",
                details: "x".into(),
            },
        ];
        for err in errors {
            let message = UserFacing::user_message(&err);
            assert!(!message.title.is_empty(), "{err:?} has no title");
            assert!(!message.summary.is_empty(), "{err:?} has no summary");
        }
    }

    #[test]
    fn missing_rows_are_reported_as_corruption() {
        let err: StorageError = rusqlite::Error::QueryReturnedNoRows.into();
        assert!(matches!(err, StorageError::Corrupt(_)));
    }

    #[test]
    fn io_errors_become_access_errors() {
        let err: StorageError =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied").into();
        assert!(matches!(err, StorageError::Access(_)));
    }
}
