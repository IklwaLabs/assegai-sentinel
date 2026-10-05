//! Shared SQL statements.
//!
//! Every write path routes through these functions: the direct [`crate::db::Database`] methods
//! used by the CLI, exports and tests, and the batched [`crate::writer::StorageWriter`] thread.
//! Having one definition per statement is what stops the writer and the ad-hoc paths from
//! drifting apart in column lists or conflict clauses.
//!
//! All statements are static and bound through [`rusqlite`] parameters. No SQL string is
//! assembled from input.

use rusqlite::{Connection, params};

use sentinel_common::clock;
use sentinel_flow::aggregate::TrafficSample;

use crate::error::Result;
use crate::schema::{FlowRecord, InterfaceRecord, ProtocolTotalRecord, to_sql_timestamp};

/// Converts an unsigned counter to SQLite's signed INTEGER, saturating on overflow.
fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Inserts or updates an interface observation, preserving the original `first_seen_us`.
pub fn upsert_interface(conn: &Connection, record: &InterfaceRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO interfaces (
             id, name, description, kind, addresses_json, mac,
             is_loopback, is_virtual, first_seen_us, last_seen_us
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             description = excluded.description,
             kind = excluded.kind,
             addresses_json = excluded.addresses_json,
             mac = excluded.mac,
             is_loopback = excluded.is_loopback,
             is_virtual = excluded.is_virtual,
             last_seen_us = excluded.last_seen_us",
        params![
            record.id,
            record.name,
            record.description,
            record.kind,
            record.addresses_json,
            record.mac,
            u8::from(record.is_loopback),
            u8::from(record.is_virtual),
            to_sql_timestamp(record.first_seen_us),
            to_sql_timestamp(record.last_seen_us),
        ],
    )?;
    Ok(())
}

/// Inserts or updates a flow row by its normalized key.
///
/// Counters and enrichment are overwritten with the newest observation. `first_seen_us` is
/// left alone on conflict: it is the flow's true start, and a later flush must not move it.
pub fn upsert_flow(conn: &Connection, record: &FlowRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO flows (
             id, protocol, endpoint_a, endpoint_b, local_addr, remote_addr,
             service, domain, process_id, process_name, state,
             bytes_sent, bytes_received, packets_sent, packets_received,
             risk_score, alert_count, tags_json, first_seen_us, last_seen_us, updated_at_us
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
             ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
         )
         ON CONFLICT(id) DO UPDATE SET
             service = excluded.service,
             domain = excluded.domain,
             process_id = excluded.process_id,
             process_name = excluded.process_name,
             state = excluded.state,
             bytes_sent = excluded.bytes_sent,
             bytes_received = excluded.bytes_received,
             packets_sent = excluded.packets_sent,
             packets_received = excluded.packets_received,
             risk_score = excluded.risk_score,
             alert_count = excluded.alert_count,
             tags_json = excluded.tags_json,
             last_seen_us = excluded.last_seen_us,
             updated_at_us = excluded.updated_at_us",
        params![
            record.id,
            record.flow.key.protocol.label(),
            record.flow.key.endpoint_a.display(),
            record.flow.key.endpoint_b.display(),
            record.local_addr,
            record.remote_addr,
            record.flow.service,
            record.flow.domain,
            record.flow.process.as_ref().map(|p| p.pid),
            record.flow.process.as_ref().map(|p| p.name.clone()),
            serde_json::to_string(&record.flow.state).unwrap_or_else(|_| "\"unknown\"".to_string()),
            to_i64(record.flow.bytes_sent),
            to_i64(record.flow.bytes_received),
            to_i64(record.flow.packets_sent),
            to_i64(record.flow.packets_received),
            record.flow.risk_score.map(i32::from),
            record.flow.alert_count,
            serde_json::to_string(&record.flow.tags).unwrap_or_else(|_| "[]".to_string()),
            to_sql_timestamp(record.flow.first_seen_us),
            to_sql_timestamp(record.flow.last_seen_us),
            to_sql_timestamp(clock::now_unix_micros()),
        ],
    )?;
    Ok(())
}

/// Adds to a traffic sample bucket, creating it when absent.
pub fn upsert_traffic_sample(conn: &Connection, sample: &TrafficSample) -> Result<()> {
    conn.execute(
        "INSERT INTO traffic_samples (bucket_start_us, upload_bytes, download_bytes, packets)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(bucket_start_us) DO UPDATE SET
             upload_bytes = traffic_samples.upload_bytes + excluded.upload_bytes,
             download_bytes = traffic_samples.download_bytes + excluded.download_bytes,
             packets = traffic_samples.packets + excluded.packets",
        params![
            to_sql_timestamp(sample.bucket_start_us),
            to_i64(sample.upload_bytes),
            to_i64(sample.download_bytes),
            to_i64(sample.packets),
        ],
    )?;
    Ok(())
}

/// Adds to a protocol total, taking the newest flow count as authoritative.
pub fn upsert_protocol_total(conn: &Connection, record: &ProtocolTotalRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO protocol_totals (protocol, bytes, packets, flows, first_seen_us, last_seen_us)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(protocol) DO UPDATE SET
             bytes = protocol_totals.bytes + excluded.bytes,
             packets = protocol_totals.packets + excluded.packets,
             flows = excluded.flows,
             last_seen_us = excluded.last_seen_us",
        params![
            record.protocol,
            to_i64(record.bytes),
            to_i64(record.packets),
            to_i64(record.flows),
            to_sql_timestamp(record.first_seen_us),
            to_sql_timestamp(record.last_seen_us),
        ],
    )?;
    Ok(())
}

/// Inserts or updates a setting.
pub fn upsert_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value, to_sql_timestamp(clock::now_unix_micros())],
    )?;
    Ok(())
}

/// Deletes flow rows last seen before `cutoff_us`.
///
/// Exposed as a statement so the retention path inside the writer thread uses the same SQL as
/// [`crate::db::Database::delete_flows_before`] rather than a second copy that could drift.
pub fn delete_flows_before(conn: &Connection, cutoff_us: u64) -> Result<u64> {
    let removed = conn.execute(
        "DELETE FROM flows WHERE last_seen_us < ?1",
        [to_sql_timestamp(cutoff_us)],
    )?;
    Ok(u64::try_from(removed).unwrap_or(0))
}

/// Deletes traffic samples older than `cutoff_us`.
pub fn delete_samples_before(conn: &Connection, cutoff_us: u64) -> Result<u64> {
    let removed = conn.execute(
        "DELETE FROM traffic_samples WHERE bucket_start_us < ?1",
        [to_sql_timestamp(cutoff_us)],
    )?;
    Ok(u64::try_from(removed).unwrap_or(0))
}
