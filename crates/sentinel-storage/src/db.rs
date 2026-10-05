//! Database handle, queries and the synchronous write API.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_common::clock;
use sentinel_flow::aggregate::TrafficSample;
use sentinel_flow::flow::Flow;

use crate::error::{Result, StorageError};
use crate::migrations;
use crate::schema::{
    FlowRecord, InterfaceRecord, ProtocolTotalRecord, from_sql_timestamp, to_sql_timestamp,
};
use crate::statements;

/// Connection tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseOptions {
    /// Write-ahead logging. Strongly recommended; disabling it only helps when copying a
    /// database file for external inspection.
    pub wal_mode: bool,
    /// How long SQLite waits on a locked database before failing, in milliseconds.
    pub busy_timeout_ms: u32,
    /// Enforce foreign key constraints.
    pub foreign_keys: bool,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        // The busy timeout is generous because the writer thread and the UI can briefly overlap,
        // and a short timeout would surface as a spurious error to the user.
        Self {
            wal_mode: true,
            busy_timeout_ms: 5_000,
            foreign_keys: true,
        }
    }
}

/// Tables whose names [`Database::row_count`] accepts.
///
/// The name cannot be a bound parameter, so it is checked against this list rather than
/// interpolated. Sentinel's own callers pass literals, but the allowlist makes that safe by
/// construction instead of by review.
const COUNTABLE_TABLES: [&str; 5] = [
    "flows",
    "interfaces",
    "traffic_samples",
    "protocol_totals",
    "settings",
];

/// An open Sentinel database.
///
/// Synchronous by design: a local desktop database has exactly one writer, so a thread owns
/// the handle and batching happens in [`crate::writer`]. Read paths used by the CLI and tests
/// use this type directly.
pub struct Database {
    conn: Connection,
    #[allow(
        dead_code,
        reason = "kept for diagnostics; pragmas are applied at open time"
    )]
    options: DatabaseOptions,
}

impl Database {
    /// Opens (or creates) a database at `path` and migrates it to the current schema.
    ///
    /// # Errors
    /// Returns [`StorageError::Access`] when the file cannot be opened, and propagates
    /// migration failures.
    pub fn open(path: impl AsRef<Path>, options: DatabaseOptions) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                StorageError::Access(format!("creating {}: {err}", parent.display()))
            })?;
        }

        let conn = Connection::open_with_flags(
            path.as_ref(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|err| {
            StorageError::Access(format!("opening {}: {err}", path.as_ref().display()))
        })?;

        let database = Self { conn, options };
        database.apply_pragmas()?;
        migrations::migrate(&database.conn)?;
        Ok(database)
    }

    /// Opens a private in-memory database, for tests and offline analysis.
    ///
    /// # Errors
    /// Returns [`StorageError`] when the in-memory database cannot be initialised.
    pub fn open_in_memory(options: DatabaseOptions) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let database = Self { conn, options };
        database.apply_pragmas()?;
        migrations::migrate(&database.conn)?;
        Ok(database)
    }

    /// Applies connection-level pragmas.
    fn apply_pragmas(&self) -> Result<()> {
        if self.options.wal_mode {
            // WAL cannot be enabled for in-memory databases; SQLite reports that harmlessly.
            let _ = self.conn.execute_batch("PRAGMA journal_mode=WAL;");
        }
        let _ = self
            .conn
            .busy_timeout(std::time::Duration::from_millis(u64::from(
                self.options.busy_timeout_ms,
            )));
        self.conn.execute_batch(&format!(
            "PRAGMA foreign_keys={}; PRAGMA synchronous=NORMAL;",
            u8::from(self.options.foreign_keys)
        ))?;
        Ok(())
    }

    /// The underlying connection, for callers that need raw access.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Current schema version.
    ///
    /// # Errors
    /// Propagates query failures.
    pub fn schema_version(&self) -> Result<u32> {
        migrations::schema_version(&self.conn)
    }

    /// Number of stored rows in a known table.
    ///
    /// # Errors
    /// Returns [`StorageError::Access`] for any name outside the known table list.
    pub fn row_count(&self, table: &str) -> Result<u64> {
        if !COUNTABLE_TABLES.contains(&table) {
            return Err(StorageError::Access(format!("unknown table '{table}'")));
        }
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = self.conn.query_row(&sql, [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Inserts or updates an interface observation.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn upsert_interface(&self, record: &InterfaceRecord) -> Result<()> {
        statements::upsert_interface(&self.conn, record)
    }

    /// Inserts or updates a flow.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn upsert_flow(&self, record: &FlowRecord) -> Result<()> {
        statements::upsert_flow(&self.conn, record)
    }

    /// Reads the most recent flows, newest first.
    ///
    /// # Errors
    /// Propagates SQLite and decode failures.
    pub fn recent_flows(&self, limit: usize) -> Result<Vec<FlowRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, protocol, endpoint_a, endpoint_b, local_addr, remote_addr,
                    service, domain, process_id, process_name, state,
                    bytes_sent, bytes_received, packets_sent, packets_received,
                    risk_score, alert_count, tags_json, first_seen_us, last_seen_us
             FROM flows
             ORDER BY last_seen_us DESC
             LIMIT ?1",
        )?;

        let rows = statement.query_map([limit as i64], row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(decode_flow_row(row?)?);
        }
        Ok(records)
    }

    /// Inserts or adds to a traffic sample bucket.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn upsert_traffic_sample(&self, sample: &TrafficSample) -> Result<()> {
        statements::upsert_traffic_sample(&self.conn, sample)
    }

    /// Reads traffic samples in a time range, oldest first.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn traffic_samples(
        &self,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<Vec<TrafficSample>> {
        let mut statement = self.conn.prepare(
            "SELECT bucket_start_us, upload_bytes, download_bytes, packets
             FROM traffic_samples
             WHERE bucket_start_us BETWEEN ?1 AND ?2
             ORDER BY bucket_start_us ASC
             LIMIT ?3",
        )?;

        let rows = statement.query_map(
            params![
                to_sql_timestamp(from_us),
                to_sql_timestamp(to_us),
                limit as i64
            ],
            |row| {
                Ok(TrafficSample {
                    bucket_start_us: from_sql_timestamp(row.get(0)?),
                    upload_bytes: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    download_bytes: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    packets: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                })
            },
        )?;

        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Adds to a protocol total.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn upsert_protocol_total(&self, record: &ProtocolTotalRecord) -> Result<()> {
        statements::upsert_protocol_total(&self.conn, record)
    }

    /// Reads every protocol total.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn protocol_totals(&self) -> Result<Vec<ProtocolTotalRecord>> {
        let mut statement = self
            .conn
            .prepare("SELECT protocol, bytes, packets, flows, first_seen_us, last_seen_us FROM protocol_totals")?;
        let rows = statement.query_map([], |row| {
            Ok(ProtocolTotalRecord {
                protocol: row.get(0)?,
                bytes: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                packets: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                flows: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                first_seen_us: from_sql_timestamp(row.get(4)?),
                last_seen_us: from_sql_timestamp(row.get(5)?),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Stores a setting value.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        statements::upsert_setting(&self.conn, key, value)
    }

    /// Reads a setting value.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// Runs `work` inside a transaction, committing on success and rolling back on error.
    ///
    /// This is the batched-write path: many rows per transaction, one commit.
    ///
    /// # Errors
    /// Propagates the closure's error after rolling back.
    pub fn transaction<T>(&mut self, work: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN")?;
        match work(&self.conn) {
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    /// Deletes flows last seen before `cutoff_us`.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn delete_flows_before(&mut self, cutoff_us: u64) -> Result<u64> {
        statements::delete_flows_before(&self.conn, cutoff_us)
    }

    /// Deletes traffic samples older than `cutoff_us`.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn delete_samples_before(&mut self, cutoff_us: u64) -> Result<u64> {
        statements::delete_samples_before(&self.conn, cutoff_us)
    }

    /// Reports a database file's size in bytes.
    ///
    /// # Errors
    /// Propagates filesystem failures.
    pub fn file_size(path: &Path) -> Result<u64> {
        Ok(std::fs::metadata(path)?.len())
    }

    /// Timestamps a flow record, used by callers that need the update time before writing.
    #[must_use]
    pub fn now_us() -> u64 {
        clock::now_unix_micros()
    }
}

/// One `flows` row, as read back from SQLite.
///
/// A row is twenty columns, which as a tuple is unreadable. Naming the shape lets the read
/// function stay a list of `row.get` calls without repeating the type everywhere.
#[allow(
    clippy::type_complexity,
    reason = "documented alias for a fixed 20-column row"
)]
type FlowRow = (
    String,         // id
    String,         // protocol
    String,         // endpoint_a
    String,         // endpoint_b
    Option<String>, // local_addr
    Option<String>, // remote_addr
    Option<String>, // service
    Option<String>, // domain
    Option<i64>,    // process_id
    Option<String>, // process_name
    String,         // state
    i64,            // bytes_sent
    i64,            // bytes_received
    i64,            // packets_sent
    i64,            // packets_received
    Option<i64>,    // risk_score
    i64,            // alert_count
    String,         // tags_json
    i64,            // first_seen_us
    i64,            // last_seen_us
);

/// Rebuilds a [`FlowRecord`] from one `flows` row.
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<FlowRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
        row.get(19)?,
    ))
}

/// Converts a `flows` row tuple into a typed record.
fn decode_flow_row(row: FlowRow) -> Result<FlowRecord> {
    let (
        id,
        protocol,
        endpoint_a,
        endpoint_b,
        local_addr,
        remote_addr,
        service,
        domain,
        process_id,
        process_name,
        state,
        bytes_sent,
        bytes_received,
        packets_sent,
        packets_received,
        risk_score,
        alert_count,
        tags_json,
        first_seen_us,
        last_seen_us,
    ) = row;

    let flow = Flow {
        key: decode_key(&protocol, &endpoint_a, &endpoint_b)?,
        state: serde_json::from_str(&state).unwrap_or(sentinel_flow::flow::FlowState::Unknown),
        first_seen_us: from_sql_timestamp(first_seen_us),
        last_seen_us: from_sql_timestamp(last_seen_us),
        bytes_sent: u64::try_from(bytes_sent).unwrap_or(0),
        bytes_received: u64::try_from(bytes_received).unwrap_or(0),
        packets_sent: u64::try_from(packets_sent).unwrap_or(0),
        packets_received: u64::try_from(packets_received).unwrap_or(0),
        service,
        domain,
        process: process_id.map(|pid| sentinel_flow::flow::ProcessRef {
            pid: u32::try_from(pid).unwrap_or(0),
            name: process_name.unwrap_or_default(),
            path: None,
            application: None,
        }),
        risk_score: risk_score.and_then(|score| u8::try_from(score).ok()),
        alert_count: u32::try_from(alert_count).unwrap_or(0),
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        initiator: None,
    };

    Ok(FlowRecord {
        id,
        flow,
        local_addr,
        remote_addr,
    })
}

/// Rebuilds a flow key from stored columns.
fn decode_key(
    protocol: &str,
    endpoint_a: &str,
    endpoint_b: &str,
) -> Result<sentinel_flow::key::FlowKey> {
    let first = parse_endpoint(endpoint_a)?;
    let second = parse_endpoint(endpoint_b)?;
    Ok(sentinel_flow::key::FlowKey::new(
        parse_protocol(protocol),
        first,
        second,
    ))
}

/// Parses `addr:port`, a bracketed IPv6 form, or a bare address for protocols without ports.
fn parse_endpoint(text: &str) -> Result<sentinel_flow::key::Endpoint> {
    use sentinel_flow::key::Endpoint;

    let text = text.trim();

    // A bare address is unambiguous, so try it first. Without this, `fd00::1` would split at
    // its last colon and the trailing "1" would be mistaken for a port.
    if let Ok(addr) = text.parse::<std::net::IpAddr>() {
        return Ok(Endpoint::new(addr, None));
    }

    // Everything remaining must be an address with a port. A bracketed IPv6 literal is
    // explicit: [addr]:port. Otherwise the port is whatever follows the final colon, and the
    // address must parse without it.
    let (addr_text, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let (addr, tail) = rest
            .split_once(']')
            .ok_or_else(|| StorageError::Corrupt(format!("unterminated bracket in '{text}'")))?;
        let port = tail.strip_prefix(':').ok_or_else(|| {
            StorageError::Corrupt(format!("missing port after bracket in '{text}'"))
        })?;
        (addr.to_string(), port.to_string())
    } else {
        let (addr, port) = text
            .rsplit_once(':')
            .ok_or_else(|| StorageError::Corrupt(format!("unparseable endpoint '{text}'")))?;
        (addr.to_string(), port.to_string())
    };

    let addr = addr_text.parse().map_err(|_| {
        StorageError::Corrupt(format!("unparseable address '{addr_text}' in '{text}'"))
    })?;
    let port = port_text.parse().map_err(|_| {
        StorageError::Corrupt(format!("unparseable port '{port_text}' in '{text}'"))
    })?;
    Ok(Endpoint::new(addr, Some(port)))
}

/// Maps a stored protocol label back to a protocol.
///
/// [`sentinel_common::packet::TransportProtocol::label`] renders an unrecognised protocol as
/// `IP(132)`, so the numeric form is parsed out of the parentheses rather than discarded.
fn parse_protocol(label: &str) -> sentinel_common::packet::TransportProtocol {
    use sentinel_common::packet::TransportProtocol;

    let upper = label.to_ascii_uppercase();
    match upper.as_str() {
        "TCP" => return TransportProtocol::Tcp,
        "UDP" => return TransportProtocol::Udp,
        "ICMP" => return TransportProtocol::Icmp,
        "ICMPV6" => return TransportProtocol::IcmpV6,
        _ => {}
    }

    let number = upper
        .strip_prefix("IP(")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|digits| digits.parse::<u8>().ok())
        .unwrap_or(0);
    TransportProtocol::Other(number)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sentinel_common::net::InterfaceAddress;
    use sentinel_common::packet::TransportProtocol;
    use sentinel_flow::flow::FlowState;
    use sentinel_flow::key::{Endpoint, FlowKey};

    use super::*;

    fn database() -> Database {
        Database::open_in_memory(DatabaseOptions::default()).expect("in-memory database")
    }

    fn flow(id_hint: u16) -> Flow {
        Flow {
            key: FlowKey::new(
                TransportProtocol::Tcp,
                Endpoint::new(
                    "192.168.1.10".parse().expect("valid"),
                    Some(50_000 + id_hint),
                ),
                Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            ),
            state: FlowState::Established,
            first_seen_us: 1_000,
            last_seen_us: 5_000,
            bytes_sent: 1_000,
            bytes_received: 9_000,
            packets_sent: 10,
            packets_received: 12,
            service: Some("HTTPS".to_string()),
            domain: Some("example.com".to_string()),
            process: Some(sentinel_flow::flow::ProcessRef {
                pid: 5812,
                name: "chrome.exe".to_string(),
                path: None,
                application: Some("Google Chrome".to_string()),
            }),
            risk_score: Some(35),
            alert_count: 1,
            tags: BTreeSet::from(["outbound".to_string()]),
            initiator: Some(sentinel_flow::key::FlowSide::B),
        }
    }

    #[test]
    fn opens_and_migrates() {
        let db = database();
        assert_eq!(
            db.schema_version().expect("version"),
            migrations::TARGET_VERSION
        );
        assert_eq!(db.row_count("flows").expect("count"), 0);
    }

    #[test]
    fn a_file_backed_database_persists_across_reopen() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("nested").join("sentinel.db");

        {
            let db = Database::open(&path, DatabaseOptions::default()).expect("open");
            db.upsert_flow(&FlowRecord::new(flow(1)))
                .expect("write flow");
        }

        let reopened = Database::open(&path, DatabaseOptions::default()).expect("reopen");
        assert_eq!(reopened.row_count("flows").expect("count"), 1);
        assert!(Database::file_size(&path).expect("size") > 0);
    }

    #[test]
    fn flows_upsert_rather_than_duplicate() {
        let db = database();
        let record = FlowRecord::new(flow(1));
        db.upsert_flow(&record).expect("first write");

        let mut updated = record.clone();
        updated.flow.bytes_sent = 5_000;
        updated.flow.state = FlowState::Closed;
        db.upsert_flow(&updated).expect("second write");

        assert_eq!(
            db.row_count("flows").expect("count"),
            1,
            "the same key must update in place"
        );
        let stored = db.recent_flows(10).expect("read");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].flow.bytes_sent, 5_000);
        assert_eq!(stored[0].flow.state, FlowState::Closed);
    }

    #[test]
    fn a_second_write_preserves_the_original_start_time() {
        let db = database();
        let mut record = FlowRecord::new(flow(1));
        record.flow.first_seen_us = 1_000;
        db.upsert_flow(&record).expect("first write");

        record.flow.first_seen_us = 4_000;
        record.flow.last_seen_us = 9_000;
        db.upsert_flow(&record).expect("second write");

        let stored = db.recent_flows(1).expect("read").remove(0);
        assert_eq!(
            stored.flow.first_seen_us, 1_000,
            "a later flush must not move the flow's start"
        );
        assert_eq!(stored.flow.last_seen_us, 9_000);
    }

    #[test]
    fn flows_round_trip_their_fields() {
        let db = database();
        let record = FlowRecord::new(flow(1));
        db.upsert_flow(&record).expect("write");

        let stored = db.recent_flows(10).expect("read").remove(0);
        assert_eq!(stored.id, record.id);
        assert_eq!(stored.flow.key, record.flow.key);
        assert_eq!(stored.flow.service.as_deref(), Some("HTTPS"));
        assert_eq!(stored.flow.domain.as_deref(), Some("example.com"));
        assert_eq!(stored.flow.process.as_ref().map(|p| p.pid), Some(5812));
        assert_eq!(stored.flow.risk_score, Some(35));
        assert_eq!(stored.flow.alert_count, 1);
        assert_eq!(stored.flow.first_seen_us, 1_000);
        assert_eq!(stored.flow.last_seen_us, 5_000);
        assert!(stored.flow.tags.contains("outbound"));
    }

    #[test]
    fn flows_are_returned_newest_first() {
        let db = database();
        for index in 0..3u16 {
            let mut record = FlowRecord::new(flow(index));
            record.flow.last_seen_us = u64::from(index) * 1_000;
            db.upsert_flow(&record).expect("write");
        }
        let times: Vec<u64> = db
            .recent_flows(10)
            .expect("read")
            .iter()
            .map(|r| r.flow.last_seen_us)
            .collect();
        assert_eq!(
            times,
            vec![2_000, 1_000, 0],
            "ordering must be newest first"
        );
    }

    #[test]
    fn traffic_samples_accumulate_per_bucket() {
        let db = database();
        let sample = TrafficSample {
            bucket_start_us: 1_000_000,
            upload_bytes: 100,
            download_bytes: 200,
            packets: 3,
        };
        db.upsert_traffic_sample(&sample).expect("first write");
        db.upsert_traffic_sample(&sample).expect("second write");

        let stored = db.traffic_samples(0, 2_000_000, 10).expect("read");
        assert_eq!(stored.len(), 1, "one bucket, not two rows");
        assert_eq!(stored[0].upload_bytes, 200);
        assert_eq!(stored[0].download_bytes, 400);
        assert_eq!(stored[0].packets, 6);
    }

    #[test]
    fn traffic_samples_respect_the_time_range() {
        let db = database();
        for second in 0..5u64 {
            db.upsert_traffic_sample(&TrafficSample {
                bucket_start_us: second * 1_000_000,
                ..TrafficSample::default()
            })
            .expect("write");
        }
        let stored = db.traffic_samples(1_000_000, 3_000_000, 10).expect("read");
        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].bucket_start_us, 1_000_000);
        assert_eq!(stored[2].bucket_start_us, 3_000_000);
    }

    #[test]
    fn interfaces_upsert_and_count() {
        let db = database();
        let mut iface = sentinel_common::net::NetworkInterface::new("3", "Ethernet");
        iface.addresses.push(InterfaceAddress::new(
            "192.168.1.10".parse().expect("valid"),
            24,
        ));

        db.upsert_interface(&InterfaceRecord::new(&iface))
            .expect("write");
        let mut renamed = iface.clone();
        renamed.name = "Ethernet 2".to_string();
        db.upsert_interface(&InterfaceRecord::new(&renamed))
            .expect("write again");

        assert_eq!(
            db.row_count("interfaces").expect("count"),
            1,
            "the same id must update"
        );
    }

    #[test]
    fn protocol_totals_accumulate() {
        let db = database();
        let record = ProtocolTotalRecord::new(
            sentinel_flow::aggregate::ProtocolTotals {
                protocol: TransportProtocol::Tcp,
                bytes: 100,
                packets: 4,
                flows: 1,
            },
            1_000,
            2_000,
        );
        db.upsert_protocol_total(&record).expect("write");
        db.upsert_protocol_total(&record).expect("write again");

        let totals = db.protocol_totals().expect("read");
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].bytes, 200);
        assert_eq!(totals[0].packets, 8);
        assert_eq!(totals[0].flows, 1);
    }

    #[test]
    fn settings_round_trip() {
        let db = database();
        assert_eq!(db.setting("theme").expect("read missing"), None);
        db.set_setting("theme", "\"dark\"").expect("write");
        assert_eq!(
            db.setting("theme").expect("read"),
            Some("\"dark\"".to_string())
        );

        db.set_setting("theme", "\"light\"").expect("overwrite");
        assert_eq!(
            db.setting("theme").expect("read"),
            Some("\"light\"".to_string())
        );
        assert_eq!(db.row_count("settings").expect("count"), 1);
    }

    #[test]
    fn unknown_tables_are_refused_before_reaching_sql() {
        let db = database();
        let err = db
            .row_count("flows; DROP TABLE flows")
            .expect_err("injection must be refused");
        assert!(matches!(err, StorageError::Access(_)));
    }

    #[test]
    fn transactions_commit_on_success_and_roll_back_on_error() {
        let mut db = database();

        db.transaction(|conn| {
            conn.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', 0)",
                [],
            )?;
            Ok(())
        })
        .expect("commit");
        assert_eq!(db.row_count("settings").expect("count"), 1);

        let outcome: Result<()> = db.transaction(|conn| {
            conn.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES ('k2', 'v', 0)",
                [],
            )?;
            Err(StorageError::Sqlite("deliberate".to_string()))
        });
        assert!(outcome.is_err());
        assert_eq!(
            db.row_count("settings").expect("count"),
            1,
            "the failed batch must not persist"
        );
    }

    #[test]
    fn deletion_removes_only_old_rows() {
        let mut db = database();
        for index in 0..3u16 {
            let mut record = FlowRecord::new(flow(index));
            record.flow.last_seen_us = u64::from(index) * 1_000_000;
            db.upsert_flow(&record).expect("write");
        }
        let removed = db.delete_flows_before(1_500_000).expect("delete");
        assert_eq!(
            removed, 2,
            "rows at 0 and 1s are older than the 1.5s cutoff"
        );
        assert_eq!(db.row_count("flows").expect("count"), 1);
    }

    #[test]
    fn endpoint_parsing_handles_ipv4_ipv6_and_portless_forms() {
        assert_eq!(parse_endpoint("10.0.0.1:53").expect("ipv4").port, Some(53));
        assert_eq!(parse_endpoint("10.0.0.1").expect("portless").port, None);

        let v6 = parse_endpoint("[2606:4700::1]:443").expect("bracketed ipv6");
        assert_eq!(v6.addr.to_string(), "2606:4700::1");
        assert_eq!(v6.port, Some(443));

        let bare_v6 = parse_endpoint("fd00::1").expect("bare ipv6");
        assert_eq!(bare_v6.addr.to_string(), "fd00::1");
        assert_eq!(bare_v6.port, None);

        // An unbracketed string that parses as a whole is a portless IPv6 address. That is the
        // correct reading: `2606:4700::1:443` is a legal address that means something different
        // from `[2606:4700::1]:443`, which is why the writer emits the bracketed form.
        let ambiguous = parse_endpoint("2606:4700::1:443").expect("parses as a bare address");
        assert_eq!(ambiguous.addr.to_string(), "2606:4700::1:443");
        assert_eq!(ambiguous.port, None);

        assert!(parse_endpoint("not-an-address").is_err());
        assert!(
            parse_endpoint("[2606:4700::1]443").is_err(),
            "a missing colon after ] is invalid"
        );
        assert!(
            parse_endpoint("[2606:4700::1]").is_err(),
            "a bracketed address must carry a port"
        );
    }

    #[test]
    fn protocol_labels_round_trip() {
        for protocol in [
            TransportProtocol::Tcp,
            TransportProtocol::Udp,
            TransportProtocol::Icmp,
        ] {
            assert_eq!(parse_protocol(protocol.label()), protocol);
        }
        assert_eq!(parse_protocol("IP(132)"), TransportProtocol::Other(132));
        assert_eq!(parse_protocol("unheard-of"), TransportProtocol::Other(0));
    }
}
