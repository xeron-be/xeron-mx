CREATE TABLE ses_identities (
    domain_id   INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    identity    TEXT    NOT NULL DEFAULT '',
    inherited   INTEGER NOT NULL DEFAULT 0,
    managed     INTEGER NOT NULL DEFAULT 0,
    status      TEXT    NOT NULL DEFAULT 'pending',
    dkim_tokens TEXT    NOT NULL DEFAULT '[]',
    last_error  TEXT    NOT NULL DEFAULT '',
    checked_at  TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE INDEX ses_identities_identity ON ses_identities(identity);
