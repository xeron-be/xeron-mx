ALTER TABLE queue ADD COLUMN auth_results TEXT NOT NULL DEFAULT '';
ALTER TABLE queue ADD COLUMN sender_authenticated INTEGER NOT NULL DEFAULT 0;

CREATE TABLE domain_recipients (
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    address   TEXT    NOT NULL,
    PRIMARY KEY (domain_id, address)
);
