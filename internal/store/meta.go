package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

func (db *DB) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: read meta %s: %w", key, err)
	}
	return v, nil
}

func (db *DB) SetMeta(ctx context.Context, key, value string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("store: write meta %s: %w", key, err)
	}
	return nil
}

func (db *DB) MetaInt(ctx context.Context, key string) (int64, error) {
	v, err := db.Meta(ctx, key)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: meta %s is not a number: %w", key, err)
	}
	return n, nil
}

func (db *DB) SetMetaInt(ctx context.Context, key string, value int64) error {
	return db.SetMeta(ctx, key, strconv.FormatInt(value, 10))
}

func (db *DB) MaxEventID(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(id) FROM events`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: max event id: %w", err)
	}
	return n.Int64, nil
}

func (db *DB) EventsSince(ctx context.Context, afterID int64, limit int) ([]*Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, type, domain_id, queue_id, user_id, data, created_at
		FROM events WHERE id > ? ORDER BY id LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: events since: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}
