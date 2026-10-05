-- Iklwa Sentinel initial schema.
--
-- Design notes that matter for future migrations:
--   * Timestamps are INTEGER microseconds since the Unix epoch. SQLite has no native
--     timestamp type; integers sort correctly and compare exactly.
--   * Flows are a working set, not a packet archive. `flows` holds aggregated per-connection
--     rows that are upserted while a flow is active and retained afterwards per policy.
--   * Raw packets are never stored. There is deliberately no packets table.
--   * Text is written in camelCase JSON columns where a structure is stored, so the schema
--     and the API contract do not drift apart.

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

-- Interfaces Sentinel has observed on this machine.
CREATE TABLE IF NOT EXISTS interfaces (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    description       TEXT,
    kind              TEXT NOT NULL,
    addresses_json    TEXT NOT NULL DEFAULT '[]',
    mac               TEXT,
    is_loopback       INTEGER NOT NULL DEFAULT 0,
    is_virtual        INTEGER NOT NULL DEFAULT 0,
    first_seen_us     INTEGER NOT NULL,
    last_seen_us      INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_interfaces_last_seen ON interfaces (last_seen_us DESC);

-- Aggregated bidirectional connections.
CREATE TABLE IF NOT EXISTS flows (
    id                TEXT PRIMARY KEY,
    protocol          TEXT NOT NULL,
    endpoint_a        TEXT NOT NULL,
    endpoint_b        TEXT NOT NULL,
    local_addr        TEXT,
    remote_addr       TEXT,
    service           TEXT,
    domain            TEXT,
    process_id        INTEGER,
    process_name      TEXT,
    state             TEXT NOT NULL,
    bytes_sent        INTEGER NOT NULL DEFAULT 0,
    bytes_received    INTEGER NOT NULL DEFAULT 0,
    packets_sent      INTEGER NOT NULL DEFAULT 0,
    packets_received  INTEGER NOT NULL DEFAULT 0,
    risk_score        INTEGER,
    alert_count       INTEGER NOT NULL DEFAULT 0,
    tags_json         TEXT NOT NULL DEFAULT '[]',
    first_seen_us     INTEGER NOT NULL,
    last_seen_us      INTEGER NOT NULL,
    updated_at_us     INTEGER NOT NULL
) STRICT;

-- The Connections view filters and sorts on these columns.
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows (last_seen_us DESC);
CREATE INDEX IF NOT EXISTS idx_flows_remote ON flows (remote_addr);
CREATE INDEX IF NOT EXISTS idx_flows_domain ON flows (domain);
CREATE INDEX IF NOT EXISTS idx_flows_service ON flows (service);
CREATE INDEX IF NOT EXISTS idx_flows_risk ON flows (risk_score DESC);

-- One-second traffic samples backing the charts.
CREATE TABLE IF NOT EXISTS traffic_samples (
    bucket_start_us   INTEGER NOT NULL,
    upload_bytes      INTEGER NOT NULL DEFAULT 0,
    download_bytes    INTEGER NOT NULL DEFAULT 0,
    packets           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start_us)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_traffic_samples_recent ON traffic_samples (bucket_start_us DESC);