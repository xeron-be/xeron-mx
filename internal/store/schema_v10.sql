ALTER TABLE domains ADD COLUMN monthly_send_limit INTEGER;

CREATE TABLE outbound_usage (
    domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    month      TEXT    NOT NULL,
    recipients INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (domain_id, month)
);
