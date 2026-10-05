//! Schema migrations.
//!
//! Migrations are plain SQL files embedded at compile time, applied in filename order inside
//! a transaction, and tracked in `schema_migrations`. No runtime migration framework and no
//! dynamic SQL generation: the diff of a migration is reviewable as SQL, which is the point.
//!
//! Adding a migration:
//! 1. Create `migrations/NNNN_description.sql`. Never edit a released file.
//! 2. Use only additive DDL (`CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE ADD COLUMN`).
//!    SQLite cannot drop columns in older versions, so destructive changes need a
//!    table-rebuild sequence written out explicitly.

use rusqlite::Connection;

use crate::error::{Result, StorageError};

/// The first schema version this build understands.
pub const MIN_SUPPORTED_VERSION: u32 = 1;
/// The schema version this build produces.
pub const TARGET_VERSION: u32 = 2;

/// One migration: a version number, a name, and the SQL to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Schema version after this migration is applied.
    pub version: u32,
    /// Short name used in error messages.
    pub name: &'static str,
    /// The SQL statements to execute.
    pub sql: &'static str,
}

/// All migrations in application order.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial",
        sql: include_str!("../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "0002_protocol_totals",
        sql: include_str!("../migrations/0002_protocol_totals.sql"),
    },
];

/// Creates the bookkeeping table if it is absent.
fn ensure_migration_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY,
             name       TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         ) STRICT;",
    )?;
    Ok(())
}

/// Reads the highest applied version, or `0` for an empty database.
fn current_version(conn: &Connection) -> Result<u32> {
    let mut statement = conn.prepare("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")?;
    let version: u32 = statement.query_row([], |row| row.get(0))?;
    Ok(version)
}

/// Brings the database up to [`TARGET_VERSION`].
///
/// # Errors
/// Returns [`StorageError::SchemaTooNew`] when the database was written by a newer build, and
/// [`StorageError::Migration`] when a migration fails. Each migration is applied in its own
/// transaction, so a failure leaves the database at the last good version.
pub fn migrate(conn: &Connection) -> Result<u32> {
    ensure_migration_table(conn)?;
    let current = current_version(conn)?;

    if current > TARGET_VERSION {
        return Err(StorageError::SchemaTooNew {
            found: current,
            supported: TARGET_VERSION,
        });
    }

    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }
        apply(conn, migration)?;
    }

    Ok(TARGET_VERSION)
}

/// Applies a single migration in its own transaction.
fn apply(conn: &Connection, migration: &Migration) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    match conn.execute_batch(migration.sql) {
        Ok(()) => {
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    migration.version,
                    migration.name,
                    sentinel_common::clock::now_unix_micros()
                ],
            )?;
            conn.execute_batch("COMMIT")?;
            tracing::debug!(
                version = migration.version,
                name = migration.name,
                "migration applied"
            );
            Ok(())
        }
        Err(err) => {
            // Rolling back keeps the database at a consistent version rather than half-applied.
            let _ = conn.execute_batch("ROLLBACK");
            Err(StorageError::Migration {
                name: migration.name.to_string(),
                details: err.to_string(),
            })
        }
    }
}

/// The version currently stored in the database.
pub fn schema_version(conn: &Connection) -> Result<u32> {
    ensure_migration_table(conn)?;
    current_version(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Connection {
        Connection::open_in_memory().expect("in-memory database")
    }

    #[test]
    fn migrations_are_contiguous_and_start_at_one() {
        assert_eq!(MIGRATIONS[0].version, MIN_SUPPORTED_VERSION);
        for pair in MIGRATIONS.windows(2) {
            assert_eq!(
                pair[1].version,
                pair[0].version + 1,
                "migration versions must be contiguous"
            );
        }
        assert_eq!(
            MIGRATIONS.last().expect("at least one migration").version,
            TARGET_VERSION
        );
    }

    #[test]
    fn migrating_an_empty_database_creates_the_expected_tables() {
        let conn = memory_db();
        assert_eq!(migrate(&conn).expect("migrate"), TARGET_VERSION);
        assert_eq!(schema_version(&conn).expect("version"), TARGET_VERSION);

        for table in [
            "settings",
            "interfaces",
            "flows",
            "traffic_samples",
            "protocol_totals",
        ] {
            let found: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap_or_else(|err| panic!("query for {table}: {err}"));
            assert_eq!(found, 1, "table {table} should exist");
        }
    }

    #[test]
    fn migrating_twice_is_a_no_op() {
        let conn = memory_db();
        migrate(&conn).expect("first migrate");
        let applied: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count migrations");
        assert_eq!(applied, MIGRATIONS.len() as i64);

        migrate(&conn).expect("second migrate");
        let applied_again: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count migrations");
        assert_eq!(
            applied_again, applied,
            "re-running migrations must not duplicate rows"
        );
    }

    #[test]
    fn no_packet_table_exists_by_design() {
        let conn = memory_db();
        migrate(&conn).expect("migrate");
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='packets'",
                [],
                |row| row.get(0),
            )
            .expect("query");
        assert_eq!(found, 0, "Sentinel must not store raw packets");
    }

    #[test]
    fn a_newer_database_is_refused() {
        let conn = memory_db();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (
                 version INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 applied_at INTEGER NOT NULL
             ) STRICT;
             INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'from_the_future', 0);",
        )
        .expect("seed future version");

        let err = migrate(&conn).expect_err("a future schema must be refused");
        assert!(matches!(
            err,
            StorageError::SchemaTooNew {
                found: 99,
                supported: TARGET_VERSION
            }
        ));
    }

    #[test]
    fn a_failing_migration_rolls_back() {
        let broken = Migration {
            version: 100,
            name: "broken",
            sql: "CREATE TABLE ok_before (id INTEGER); THIS IS NOT SQL;",
        };
        let conn = memory_db();
        ensure_migration_table(&conn).expect("migration table");

        let err = apply(&conn, &broken).expect_err("invalid SQL must fail");
        assert!(matches!(err, StorageError::Migration { .. }));

        let leftover: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ok_before'",
                [],
                |row| row.get(0),
            )
            .expect("query");
        assert_eq!(
            leftover, 0,
            "a rolled-back migration must leave nothing behind"
        );
    }
}
