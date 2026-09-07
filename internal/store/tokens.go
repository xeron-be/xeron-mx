package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type APIToken struct {
	ID         int64
	Name       string
	Prefix     string
	Role       string
	CreatedBy  *int64
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

func (t *APIToken) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !t.ExpiresAt.After(now)
}

func (db *DB) CreateAPIToken(ctx context.Context, t *APIToken, hash string) (int64, error) {
	var expires any
	if t.ExpiresAt != nil {
		expires = formatTime(*t.ExpiresAt)
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO api_tokens (name, prefix, token_hash, role, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(t.Name), t.Prefix, hash, t.Role, t.CreatedBy,
		formatTime(time.Now().UTC()), expires)
	if err != nil {
		return 0, fmt.Errorf("store: create api token: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) APITokenByHash(ctx context.Context, hash string) (*APIToken, error) {
	t, err := db.scanAPIToken(db.QueryRowContext(ctx, apiTokenCols+` WHERE token_hash = ?`, hash))
	if err != nil {
		return nil, err
	}
	if t.Expired(time.Now().UTC()) {
		return nil, ErrNotFound
	}
	return t, nil
}

func (db *DB) ListAPITokens(ctx context.Context) ([]*APIToken, error) {
	rows, err := db.QueryContext(ctx, apiTokenCols+` ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list api tokens: %w", err)
	}
	defer rows.Close()

	var out []*APIToken
	for rows.Next() {
		t, err := scanAPITokenRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) DeleteAPIToken(ctx context.Context, id int64) error {
	return db.exec(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
}

func (db *DB) TouchAPIToken(ctx context.Context, id int64) {
	now := time.Now().UTC()
	_, _ = db.ExecContext(ctx, `
		UPDATE api_tokens SET last_used_at = ?
		WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		formatTime(now), id, formatTime(now.Add(-time.Minute)))
}

const apiTokenCols = `
	SELECT id, name, prefix, role, created_by, created_at, expires_at, last_used_at
	FROM api_tokens`

func (db *DB) scanAPIToken(row rowScanner) (*APIToken, error) {
	t, err := scanAPITokenRow(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return t, err
}

func scanAPITokenRow(row rowScanner) (*APIToken, error) {
	var (
		t         APIToken
		createdBy sql.NullInt64
		created   string
		expires   sql.NullString
		lastUsed  sql.NullString
	)
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.Role, &createdBy, &created, &expires, &lastUsed)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan api token: %w", err)
	}
	if createdBy.Valid {
		t.CreatedBy = &createdBy.Int64
	}
	if t.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if t.ExpiresAt, err = nullTime(expires); err != nil {
		return nil, err
	}
	if t.LastUsedAt, err = nullTime(lastUsed); err != nil {
		return nil, err
	}
	return &t, nil
}
