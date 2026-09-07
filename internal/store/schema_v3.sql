-- Schema version 3: content filters, and the quarantine they feed.

-- Rules an operator writes to act on mail before it is queued for delivery.
--
-- The pattern is a Go regexp, which is RE2: no backreferences, and no
-- catastrophic backtracking. That matters because these run on every message
-- that arrives, and a pattern that took exponential time would be a way to stop
-- the server by sending it one email.
CREATE TABLE filters (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    -- Which envelope or header value the pattern is matched against. "to"
    -- matches if any single recipient matches.
    field         TEXT    NOT NULL CHECK (field IN ('from', 'to', 'subject')),
    pattern       TEXT    NOT NULL,
    -- reject refuses at SMTP time with a 5xx. quarantine accepts the message
    -- and holds it out of delivery. allow stops evaluation and delivers, which
    -- is what makes an exception to a broader rule below it possible.
    action        TEXT    NOT NULL CHECK (action IN ('reject', 'quarantine', 'allow')),
    enabled       INTEGER NOT NULL DEFAULT 1,
    -- Lowest first. Ties break on id, so the order is always deterministic.
    priority      INTEGER NOT NULL DEFAULT 100,
    match_count   INTEGER NOT NULL DEFAULT 0,
    last_match_at TEXT,
    created_at    TEXT    NOT NULL
);

CREATE INDEX idx_filters_order ON filters(enabled, priority, id);

-- Quarantine is expressed as two nullable columns rather than a new status.
--
-- The status column carries a CHECK constraint, and SQLite cannot alter one
-- without rebuilding the table — which would mean copying the whole queue on
-- upgrade. More importantly, a quarantined message keeps its real lifecycle
-- state: it is still 'queued', still counts against retention, and is released
-- back into delivery by clearing these two columns rather than by guessing what
-- its status used to be.
ALTER TABLE queue ADD COLUMN quarantined_at TEXT;
ALTER TABLE queue ADD COLUMN quarantine_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_queue_quarantine ON queue(quarantined_at);
