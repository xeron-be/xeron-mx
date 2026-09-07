CREATE TABLE domains (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL UNIQUE,
    primary_host        TEXT    NOT NULL,
    primary_port        INTEGER NOT NULL DEFAULT 25,
    primary_tls         TEXT    NOT NULL DEFAULT 'opportunistic'
                                CHECK (primary_tls IN ('none', 'opportunistic', 'starttls', 'tls')),
    max_queue_messages  INTEGER,
    retention_hours     INTEGER NOT NULL DEFAULT 168,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL
);

CREATE TABLE queue (
    id              TEXT    PRIMARY KEY,
    domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    envelope_from   TEXT    NOT NULL,
    envelope_to     TEXT    NOT NULL,
    subject         TEXT    NOT NULL DEFAULT '',
    size_bytes      INTEGER NOT NULL,
    received_at     TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'queued'
                            CHECK (status IN ('queued','delivering','delivered','failed','expired')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_retry_at   TEXT    NOT NULL,
    last_error      TEXT    NOT NULL DEFAULT '',
    delivered_at    TEXT,
    claimed_at      TEXT,
    claimed_by      TEXT    NOT NULL DEFAULT '',
    remote_addr     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_queue_pickup  ON queue(status, next_retry_at);
CREATE INDEX idx_queue_domain  ON queue(domain_id, status);
CREATE INDEX idx_queue_expiry  ON queue(status, expires_at);

CREATE TABLE primary_status (
    domain_id            INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    is_up                INTEGER NOT NULL DEFAULT 0,
    last_check           TEXT,
    last_up              TEXT,
    last_down            TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_success  INTEGER NOT NULL DEFAULT 0,
    last_error           TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','viewer')),
    created_at    TEXT    NOT NULL,
    last_login_at TEXT
);

CREATE TABLE sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    user_agent TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,
    domain_id  INTEGER REFERENCES domains(id) ON DELETE SET NULL,
    queue_id   TEXT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    data       TEXT    NOT NULL DEFAULT '{}',
    created_at TEXT    NOT NULL
);

CREATE INDEX idx_events_created ON events(created_at DESC);
CREATE INDEX idx_events_queue   ON events(queue_id);
