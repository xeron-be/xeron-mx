ALTER TABLE queue ADD COLUMN spam_score REAL;
ALTER TABLE queue ADD COLUMN spam_action TEXT NOT NULL DEFAULT '';

ALTER TABLE queue ADD COLUMN direction TEXT NOT NULL DEFAULT 'inbound'
    CHECK (direction IN ('inbound', 'outbound'));

CREATE INDEX idx_queue_direction ON queue(direction, status, next_retry_at);

CREATE TABLE smtp_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    allowed_domains TEXT  NOT NULL DEFAULT '[]',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT
);
