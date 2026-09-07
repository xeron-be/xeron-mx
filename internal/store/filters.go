package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	FieldFrom    = "from"
	FieldTo      = "to"
	FieldSubject = "subject"

	FilterReject     = "reject"
	FilterQuarantine = "quarantine"
	FilterAllow      = "allow"
)

type Filter struct {
	ID          int64
	Name        string
	Field       string
	Pattern     string
	Action      string
	Enabled     bool
	Priority    int
	MatchCount  int64
	LastMatchAt *time.Time
	CreatedAt   time.Time
}

func ValidFilterField(f string) bool {
	switch f {
	case FieldFrom, FieldTo, FieldSubject:
		return true
	}
	return false
}

func ValidFilterAction(a string) bool {
	switch a {
	case FilterReject, FilterQuarantine, FilterAllow:
		return true
	}
	return false
}

func (db *DB) CreateFilter(ctx context.Context, f *Filter) (int64, error) {
	res, err := db.ExecContext(ctx, `
		INSERT INTO filters (name, field, pattern, action, enabled, priority, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(f.Name), f.Field, f.Pattern, f.Action,
		boolToInt(f.Enabled), f.Priority, formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: create filter: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) UpdateFilter(ctx context.Context, f *Filter) error {
	return db.exec(ctx, `
		UPDATE filters
		SET name = ?, field = ?, pattern = ?, action = ?, enabled = ?, priority = ?
		WHERE id = ?`,
		strings.TrimSpace(f.Name), f.Field, f.Pattern, f.Action,
		boolToInt(f.Enabled), f.Priority, f.ID)
}

func (db *DB) DeleteFilter(ctx context.Context, id int64) error {
	return db.exec(ctx, `DELETE FROM filters WHERE id = ?`, id)
}

func (db *DB) FilterByID(ctx context.Context, id int64) (*Filter, error) {
	return db.scanFilter(db.QueryRowContext(ctx, filterCols+` WHERE id = ?`, id))
}

func (db *DB) ListFilters(ctx context.Context) ([]*Filter, error) {
	rows, err := db.QueryContext(ctx, filterCols+` ORDER BY priority, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list filters: %w", err)
	}
	defer rows.Close()

	var out []*Filter
	for rows.Next() {
		f, err := scanFilterRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) RecordFilterMatch(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, `
		UPDATE filters SET match_count = match_count + 1, last_match_at = ? WHERE id = ?`,
		formatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store: record filter match: %w", err)
	}
	return nil
}

const filterCols = `
	SELECT id, name, field, pattern, action, enabled, priority,
	       match_count, last_match_at, created_at
	FROM filters`

func (db *DB) scanFilter(row rowScanner) (*Filter, error) {
	f, err := scanFilterRow(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return f, err
}

func scanFilterRow(row rowScanner) (*Filter, error) {
	var (
		f         Filter
		enabled   int
		lastMatch sql.NullString
		created   string
	)
	err := row.Scan(&f.ID, &f.Name, &f.Field, &f.Pattern, &f.Action, &enabled,
		&f.Priority, &f.MatchCount, &lastMatch, &created)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan filter: %w", err)
	}
	f.Enabled = enabled != 0
	if f.LastMatchAt, err = nullTime(lastMatch); err != nil {
		return nil, err
	}
	if f.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	return &f, nil
}

func (db *DB) Quarantine(ctx context.Context, id, reason string) error {
	return db.exec(ctx, `
		UPDATE queue SET quarantined_at = ?, quarantine_reason = ?
		WHERE id = ? AND quarantined_at IS NULL`,
		formatTime(time.Now().UTC()), truncate(reason, 500), id)
}

func (db *DB) Release(ctx context.Context, id string, now time.Time) error {
	return db.exec(ctx, `
		UPDATE queue
		SET quarantined_at = NULL, quarantine_reason = '',
		    status = 'queued', next_retry_at = ?
		WHERE id = ? AND quarantined_at IS NOT NULL`,
		formatTime(now), id)
}

func (db *DB) CountQuarantined(ctx context.Context) (int64, error) {
	var n int64
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM queue WHERE quarantined_at IS NOT NULL`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count quarantined: %w", err)
	}
	return n, nil
}
