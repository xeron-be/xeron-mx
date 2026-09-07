CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','operator','viewer')),
    created_at    TEXT    NOT NULL,
    last_login_at TEXT,
    oidc_subject  TEXT,
    oidc_issuer   TEXT,
    allowed_domains TEXT NOT NULL DEFAULT '[]'
);

INSERT INTO users_new (id, email, password_hash, role, created_at, last_login_at, oidc_subject, oidc_issuer)
    SELECT id, email, password_hash, role, created_at, last_login_at, oidc_subject, oidc_issuer FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc ON users(oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;
