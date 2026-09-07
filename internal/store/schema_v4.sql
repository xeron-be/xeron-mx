-- Schema version 4: DKIM signing keys, and per-destination outbound routing.

-- One signing key per domain.
--
-- private_key is sealed with the same master key the spool uses, never stored
-- as plaintext PEM. Someone who reads this table without that key gets nothing
-- usable: a DKIM private key signs mail as the domain, which is a credential in
-- every sense that matters, unlike the password hashes next door.
CREATE TABLE dkim_keys (
    domain_id   INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    selector    TEXT    NOT NULL,
    -- rsa keys interoperate everywhere; ed25519 is smaller and faster but some
    -- verifiers still do not know it, so the choice is recorded per key.
    algorithm   TEXT    NOT NULL DEFAULT 'rsa' CHECK (algorithm IN ('rsa', 'ed25519')),
    private_key BLOB    NOT NULL,
    public_key  TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL
);

-- Where outbound mail for a given destination should go.
--
-- Without a match the global outbound settings apply, which is what every
-- existing deployment already has. A route exists to say "mail to this
-- destination takes a different path" — a customer whose provider only accepts
-- mail from their own relay, or a destination that must go direct rather than
-- through a smarthost that is blocked there.
CREATE TABLE routes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The recipient domain this route applies to. A leading "." matches
    -- subdomains too: ".example.com" covers mail.example.com but not
    -- example.com itself, which is the convention every MTA uses.
    destination TEXT    NOT NULL UNIQUE,
    mode        TEXT    NOT NULL CHECK (mode IN ('relay', 'direct')),
    relay_host  TEXT    NOT NULL DEFAULT '',
    relay_port  INTEGER NOT NULL DEFAULT 587,
    relay_tls   TEXT    NOT NULL DEFAULT 'starttls'
                        CHECK (relay_tls IN ('none', 'opportunistic', 'starttls', 'tls')),
    relay_username TEXT NOT NULL DEFAULT '',
    relay_password BLOB,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL
);

CREATE INDEX idx_routes_destination ON routes(enabled, destination);
