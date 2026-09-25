package store

import (
	"context"
	"fmt"
	"time"
)

func usageMonth(now time.Time) string { return now.UTC().Format("2006-01") }

func (db *DB) SentThisMonth(ctx context.Context, domainID int64, now time.Time) (int64, error) {
	var n int64
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(recipients), 0) FROM outbound_usage WHERE domain_id = ? AND month = ?`,
		domainID, usageMonth(now)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: read sending usage: %w", err)
	}
	return n, nil
}

func (db *DB) ReserveSends(ctx context.Context, domainID int64, n int64, limit *int64, now time.Time) (ok bool, before int64, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, fmt.Errorf("store: begin sending reservation: %w", err)
	}
	defer tx.Rollback()

	month := usageMonth(now)
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(recipients), 0) FROM outbound_usage WHERE domain_id = ? AND month = ?`,
		domainID, month).Scan(&before); err != nil {
		return false, 0, fmt.Errorf("store: read sending usage: %w", err)
	}
	if limit != nil && before+n > *limit {
		return false, before, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO outbound_usage (domain_id, month, recipients) VALUES (?, ?, ?)
		ON CONFLICT (domain_id, month) DO UPDATE SET recipients = recipients + excluded.recipients`,
		domainID, month, n); err != nil {
		return false, before, fmt.Errorf("store: record sending usage: %w", err)
	}
	return true, before, tx.Commit()
}

func (db *DB) ReleaseSends(ctx context.Context, domainID int64, n int64, now time.Time) error {
	return db.exec(ctx, `
		UPDATE outbound_usage SET recipients = MAX(recipients - ?, 0)
		WHERE domain_id = ? AND month = ?`, n, domainID, usageMonth(now))
}
