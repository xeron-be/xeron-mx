CREATE TABLE sending_stats (
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    hour      TEXT    NOT NULL,
    sent      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (domain_id, hour)
);

CREATE TABLE sending_feedback (
    id             INTEGER PRIMARY KEY,
    domain_id      INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind           TEXT    NOT NULL,
    sender         TEXT    NOT NULL,
    recipient      TEXT    NOT NULL,
    feedback_id    TEXT    NOT NULL,
    ses_message_id TEXT    NOT NULL DEFAULT '',
    detail         TEXT    NOT NULL DEFAULT '',
    occurred_at    TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    UNIQUE (feedback_id, recipient)
);

CREATE INDEX sending_feedback_domain ON sending_feedback(domain_id, occurred_at);

CREATE TABLE sending_state (
    domain_id        INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    suspended_at     TEXT,
    suspended_reason TEXT NOT NULL DEFAULT '',
    suspended_by     TEXT NOT NULL DEFAULT '',
    warned_at        TEXT,
    counted_since    TEXT
);
