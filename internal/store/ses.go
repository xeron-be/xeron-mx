package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const (
	SESPending  = "pending"
	SESVerified = "verified"
	SESFailed   = "failed"
	SESError    = "error"
)

type SESIdentity struct {
	DomainID   int64
	Identity   string
	Inherited  bool
	Managed    bool
	Status     string
	DKIMTokens []string
	LastError  string
	CheckedAt  *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (db *DB) SaveSESIdentity(ctx context.Context, s *SESIdentity) error {
	tokens := s.DKIMTokens
	if tokens == nil {
		tokens = []string{}
	}
	raw, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	var checked any
	if s.CheckedAt != nil {
		checked = formatTime(*s.CheckedAt)
	}
	now := formatTime(time.Now().UTC())
	_, err = db.ExecContext(ctx, `
		INSERT INTO ses_identities (domain_id, identity, inherited, managed, status, dkim_tokens,
		                            last_error, checked_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain_id) DO UPDATE SET
			identity = excluded.identity,
			inherited = excluded.inherited,
			managed = excluded.managed,
			status = excluded.status,
			dkim_tokens = excluded.dkim_tokens,
			last_error = excluded.last_error,
			checked_at = excluded.checked_at,
			updated_at = excluded.updated_at`,
		s.DomainID, s.Identity, boolToInt(s.Inherited), boolToInt(s.Managed), s.Status,
		string(raw), s.LastError, checked, now, now)
	if err != nil {
		return fmt.Errorf("store: save ses identity: %w", err)
	}
	return nil
}

const sesCols = `
	SELECT domain_id, identity, inherited, managed, status, dkim_tokens, last_error,
	       checked_at, created_at, updated_at
	FROM ses_identities`

func (db *DB) SESIdentityFor(ctx context.Context, domainID int64) (*SESIdentity, error) {
	s, err := scanSESIdentity(db.QueryRowContext(ctx, sesCols+` WHERE domain_id = ?`, domainID))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return s, err
}

func (db *DB) ListSESIdentities(ctx context.Context) ([]*SESIdentity, error) {
	rows, err := db.QueryContext(ctx, sesCols+` ORDER BY domain_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list ses identities: %w", err)
	}
	defer rows.Close()
	var out []*SESIdentity
	for rows.Next() {
		s, err := scanSESIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) SESDependents(ctx context.Context, identity string, except int64) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT d.name FROM ses_identities s JOIN domains d ON d.id = s.domain_id
		WHERE s.identity = ? AND s.domain_id <> ? AND s.inherited = 1
		ORDER BY d.name`, normalizeDomain(identity), except)
	if err != nil {
		return nil, fmt.Errorf("store: ses dependents: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (db *DB) DeleteSESIdentity(ctx context.Context, domainID int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM ses_identities WHERE domain_id = ?`, domainID)
	if err != nil {
		return fmt.Errorf("store: delete ses identity: %w", err)
	}
	return nil
}

func scanSESIdentity(row rowScanner) (*SESIdentity, error) {
	var (
		s                  SESIdentity
		inherited, managed int
		tokens             string
		checked            sql.NullString
		created, updated   string
	)
	if err := row.Scan(&s.DomainID, &s.Identity, &inherited, &managed, &s.Status, &tokens,
		&s.LastError, &checked, &created, &updated); err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("store: scan ses identity: %w", err)
	}
	s.Inherited = inherited != 0
	s.Managed = managed != 0
	if err := json.Unmarshal([]byte(tokens), &s.DKIMTokens); err != nil {
		return nil, fmt.Errorf("store: ses dkim tokens: %w", err)
	}
	var err error
	if s.CheckedAt, err = nullTime(checked); err != nil {
		return nil, err
	}
	if s.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if s.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	return &s, nil
}
