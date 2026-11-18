-- Detection findings.
--
-- A finding is the output of the detection engine: something Sentinel decided was worth
-- reporting, with the severity it could cause, the confidence that it is real, and the evidence
-- behind it. Findings are deduplicated by identity in memory, so this table grows with distinct
-- behaviours rather than with packets.
--
-- The row keeps the pieces rather than a serialised blob because the interface sorts by severity
-- and filters by kind. The two structured fields (evidence and advice) are JSON: they are only
-- ever rendered whole, never queried.

CREATE TABLE IF NOT EXISTS findings (
    id             TEXT NOT NULL PRIMARY KEY,
    kind           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    -- The numeric form of the same severity, so ordering in SQL matches the ordering in Rust.
    -- Keeping both lets a row round-trip its label while still being sorted correctly.
    severity_rank  INTEGER NOT NULL,
    confidence     TEXT NOT NULL,
    title          TEXT NOT NULL,
    detail         TEXT NOT NULL,
    source         TEXT,
    destination    TEXT,
    first_seen_us  INTEGER NOT NULL,
    last_seen_us   INTEGER NOT NULL,
    occurrences    INTEGER NOT NULL DEFAULT 1,
    evidence_json  TEXT NOT NULL DEFAULT '[]',
    advice_json    TEXT NOT NULL DEFAULT '[]',
    updated_at_us  INTEGER NOT NULL
) STRICT;

-- The two orderings the product actually uses: most severe first for the list, and most recent
-- first for "what happened while I was away".
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings (last_seen_us DESC);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity_rank DESC, last_seen_us DESC);
