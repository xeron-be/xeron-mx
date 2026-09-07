-- Schema version 5: API tokens, event webhooks, OIDC identities, cluster peers.

-- Credentials for non-browser clients: the companion CLI, CI jobs, a monitoring
-- script.
--
-- Only the SHA-256 of the token is stored, never the token. Argon2 is
-- deliberately not used here, and the difference from the users table is not an
-- oversight: Argon2 exists to make guessing a low-entropy human password slow.
-- A token is 256 bits of rand.Read, so there is nothing to guess, and hashing
-- it on every single API call would only be a way to attack ourselves.
CREATE TABLE api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    -- The first characters of the token, kept in clear so an operator can tell
    -- two tokens apart in a list without being able to reconstruct either.
    prefix        TEXT    NOT NULL,
    token_hash    TEXT    NOT NULL UNIQUE,
    role          TEXT    NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT,
    last_used_at  TEXT
);

CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash);

-- Where to POST events as they happen.
--
-- This is not the alerting webhook in the config file. That one carries four
-- hand-written operator alerts to a single URL. This is the event stream: any
-- subscriber, any subset of event types, delivered with retries and a log of
-- what happened.
CREATE TABLE webhooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    -- Sealed with the master key the spool uses. The secret is what the
    -- receiving end checks our signature against: whoever holds it can forge
    -- notifications that look like ours.
    secret      BLOB,
    -- JSON array of event types. An empty array means every event, which is
    -- stored as '[]' rather than NULL so the column never needs a null check.
    events      TEXT    NOT NULL DEFAULT '[]',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL,
    last_error  TEXT    NOT NULL DEFAULT '',
    last_success_at TEXT
);

-- The delivery outbox, not just a log.
--
-- A row is written before the first attempt and updated as attempts happen, so
-- a restart mid-retry resumes instead of dropping the notification. For a
-- daemon whose whole promise is "nothing is lost", holding queued webhooks only
-- in memory would be the wrong half of that promise.
CREATE TABLE webhook_deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id      INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type      TEXT    NOT NULL,
    payload         TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'delivered', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT    NOT NULL,
    status_code     INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL,
    delivered_at    TEXT
);

CREATE INDEX idx_webhook_deliveries_pickup ON webhook_deliveries(status, next_attempt_at);
CREATE INDEX idx_webhook_deliveries_hook   ON webhook_deliveries(webhook_id, id DESC);

-- What the other nodes in the cluster last told us about themselves.
--
-- This table is a cache of gossip, not a source of truth: every row is
-- something a peer said about itself over the cluster API. It exists so the UI
-- can show the fleet, and so config drift between nodes becomes visible instead
-- of being discovered when a domain works on one MX and not the other.
CREATE TABLE cluster_nodes (
    node_id       TEXT    PRIMARY KEY,
    advertise_url TEXT    NOT NULL DEFAULT '',
    version       TEXT    NOT NULL DEFAULT '',
    role          TEXT    NOT NULL DEFAULT 'follower' CHECK (role IN ('primary', 'follower')),
    config_hash   TEXT    NOT NULL DEFAULT '',
    queue_pending INTEGER NOT NULL DEFAULT 0,
    queue_bytes   INTEGER NOT NULL DEFAULT 0,
    domains       INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL
);

-- The subject claim from the identity provider, which is the only stable
-- identifier OIDC guarantees. Emails get reassigned; subs do not.
--
-- A partial unique index rather than a UNIQUE column, because ALTER TABLE ADD
-- COLUMN cannot carry one, and every row that predates OIDC is NULL.
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
ALTER TABLE users ADD COLUMN oidc_issuer  TEXT;

CREATE UNIQUE INDEX idx_users_oidc ON users(oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

-- Small, boring key/value scratchpad for daemon bookkeeping that has no natural
-- table of its own — currently the webhook dispatcher's position in the event
-- log. Kept deliberately generic so the next such need does not add a migration.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
