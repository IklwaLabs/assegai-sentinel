-- Per-protocol session totals.
--
-- These come straight from the traffic aggregator's protocol breakdown, which the engine
-- maintains from the first milestone. They are stored so the Overview page can show a
-- protocol mix without recomputing it from flows.

CREATE TABLE IF NOT EXISTS protocol_totals (
    protocol          TEXT NOT NULL,
    bytes             INTEGER NOT NULL DEFAULT 0,
    packets           INTEGER NOT NULL DEFAULT 0,
    flows             INTEGER NOT NULL DEFAULT 0,
    first_seen_us     INTEGER NOT NULL,
    last_seen_us      INTEGER NOT NULL,
    PRIMARY KEY (protocol)
) STRICT;

-- Device inventory deliberately arrives with the v0.2 milestone, together with the writer
-- that populates it. Creating an empty table now would mean shipping a schema with no
-- behaviour behind it, which is worse than a missing table.