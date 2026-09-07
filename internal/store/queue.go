package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

var ErrNotFound = errors.New("store: not found")

var ErrQueueFull = errors.New("store: queue full")

func (db *DB) Enqueue(ctx context.Context, m *Message) error {
	to, err := json.Marshal(m.EnvelopeTo)
	if err != nil {
		return fmt.Errorf("store: marshal recipients: %w", err)
	}
	direction := m.Direction
	if direction == "" {
		direction = DirectionInbound
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO queue (id, domain_id, envelope_from, envelope_to, subject,
		                   size_bytes, received_at, expires_at, status,
		                   attempts, next_retry_at, remote_addr,
		                   direction, spam_score, spam_action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?, ?)`,
		m.ID, m.DomainID, m.EnvelopeFrom, string(to), m.Subject,
		m.SizeBytes, formatTime(m.ReceivedAt), formatTime(m.ExpiresAt),
		formatTime(m.NextRetryAt), m.RemoteAddr,
		string(direction), m.SpamScore, m.SpamAction)
	if err != nil {
		return fmt.Errorf("store: enqueue: %w", err)
	}
	return nil
}

type QueueStats struct {
	Pending      int64
	PendingBytes int64
	Total        int64
}

func (db *DB) Stats(ctx context.Context) (QueueStats, error) {
	var s QueueStats
	err := db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN status IN ('queued','delivering') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status IN ('queued','delivering') THEN size_bytes ELSE 0 END), 0),
			COUNT(*)
		FROM queue`).Scan(&s.Pending, &s.PendingBytes, &s.Total)
	if err != nil {
		return s, fmt.Errorf("store: stats: %w", err)
	}
	return s, nil
}

func (db *DB) StatsForDomains(ctx context.Context, domainIDs []int64) (QueueStats, error) {
	if len(domainIDs) == 0 {
		return QueueStats{}, nil
	}
	placeholders := make([]string, len(domainIDs))
	args := make([]any, len(domainIDs))
	for i, id := range domainIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")

	var s QueueStats
	query := fmt.Sprintf(`
		SELECT
			COALESCE(SUM(CASE WHEN status IN ('queued','delivering') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status IN ('queued','delivering') THEN size_bytes ELSE 0 END), 0),
			COUNT(*)
		FROM queue
		WHERE domain_id IN (%s)`, inClause)
	err := db.QueryRowContext(ctx, query, args...).Scan(&s.Pending, &s.PendingBytes, &s.Total)
	if err != nil {
		return s, fmt.Errorf("store: stats for domains: %w", err)
	}
	return s, nil
}

func (db *DB) CountQuarantinedForDomains(ctx context.Context, domainIDs []int64) (int64, error) {
	if len(domainIDs) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(domainIDs))
	args := make([]any, len(domainIDs))
	for i, id := range domainIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")
	query := fmt.Sprintf(`SELECT COUNT(*) FROM queue WHERE quarantined_at IS NOT NULL AND domain_id IN (%s)`, inClause)
	var n int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count quarantined for domains: %w", err)
	}
	return n, nil
}

func (db *DB) CountPendingForDomain(ctx context.Context, domainID int64) (int64, error) {
	var n int64
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM queue
		WHERE domain_id = ? AND status IN ('queued','delivering')`, domainID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count pending: %w", err)
	}
	return n, nil
}

func (db *DB) ClaimBatch(ctx context.Context, workerID string, limit int, now time.Time) ([]*Message, error) {
	rows, err := db.QueryContext(ctx, `
		UPDATE queue
		SET status = 'delivering', claimed_at = ?, claimed_by = ?
		WHERE id IN (
			SELECT q.id FROM queue q
			JOIN domains d        ON d.id = q.domain_id
			JOIN primary_status p ON p.domain_id = q.domain_id
			WHERE q.status = 'queued'
			  AND q.quarantined_at IS NULL
			  AND q.direction = 'inbound'
			  AND q.next_retry_at <= ?
			  AND d.enabled = 1
			  AND p.is_up = 1
			ORDER BY q.next_retry_at
			LIMIT ?
		)
		RETURNING id, domain_id, envelope_from, envelope_to, subject, size_bytes,
		          received_at, expires_at, status, attempts, next_retry_at,
		          last_error, delivered_at, remote_addr, direction,
		          spam_score, spam_action, quarantined_at, quarantine_reason`,
		formatTime(now), workerID, formatTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim batch: %w", err)
	}
	defer rows.Close()
	return scanMessages(rows)
}

func (db *DB) ClaimOutboundBatch(ctx context.Context, workerID string, limit int, now time.Time) ([]*Message, error) {
	rows, err := db.QueryContext(ctx, `
		UPDATE queue
		SET status = 'delivering', claimed_at = ?, claimed_by = ?
		WHERE id IN (
			SELECT q.id FROM queue q
			JOIN domains d ON d.id = q.domain_id
			WHERE q.status = 'queued'
			  AND q.quarantined_at IS NULL
			  AND q.direction = 'outbound'
			  AND q.next_retry_at <= ?
			  AND d.enabled = 1
			ORDER BY q.next_retry_at
			LIMIT ?
		)
		RETURNING id, domain_id, envelope_from, envelope_to, subject, size_bytes,
		          received_at, expires_at, status, attempts, next_retry_at,
		          last_error, delivered_at, remote_addr, direction,
		          spam_score, spam_action, quarantined_at, quarantine_reason`,
		formatTime(now), workerID, formatTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: claim outbound batch: %w", err)
	}
	defer rows.Close()
	return scanMessages(rows)
}

func (db *DB) MarkDelivered(ctx context.Context, id string, at time.Time) error {
	return db.exec(ctx, `
		UPDATE queue
		SET status = 'delivered', delivered_at = ?, last_error = '',
		    claimed_at = NULL, claimed_by = ''
		WHERE id = ?`, formatTime(at), id)
}

func (db *DB) MarkFailed(ctx context.Context, id, reason string) error {
	return db.exec(ctx, `
		UPDATE queue
		SET status = 'failed', last_error = ?, attempts = attempts + 1,
		    claimed_at = NULL, claimed_by = ''
		WHERE id = ?`, truncate(reason, 1000), id)
}

func (db *DB) Reschedule(ctx context.Context, id string, attempts int, reason string, base, max time.Duration, now time.Time) error {
	next := now.Add(Backoff(attempts, base, max))
	return db.exec(ctx, `
		UPDATE queue
		SET status = 'queued', attempts = ?, last_error = ?, next_retry_at = ?,
		    claimed_at = NULL, claimed_by = ''
		WHERE id = ?`, attempts, truncate(reason, 1000), formatTime(next), id)
}

func Backoff(attempts int, base, max time.Duration) time.Duration {
	if attempts < 1 {
		attempts = 1
	}

	exp := attempts - 1
	if exp > 32 {
		exp = 32
	}
	d := float64(base) * math.Pow(2, float64(exp))
	if d > float64(max) {
		d = float64(max)
	}

	half := d / 2
	return time.Duration(half + rand.Float64()*half)
}

func (db *DB) ExpireOverdue(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		UPDATE queue
		SET status = 'expired',
		    last_error = 'retention exceeded before the primary accepted it'
		WHERE status = 'queued' AND quarantined_at IS NULL AND expires_at <= ?
		RETURNING id`, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: expire: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (db *DB) ReleaseOrphanedClaims(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE queue
		SET status = 'queued', claimed_at = NULL, claimed_by = '',
		    last_error = 'delivery interrupted, requeued'
		WHERE status = 'delivering' AND (claimed_at IS NULL OR claimed_at <= ?)`,
		formatTime(olderThan))
	if err != nil {
		return 0, fmt.Errorf("store: release claims: %w", err)
	}
	return res.RowsAffected()
}

func (db *DB) GetMessage(ctx context.Context, id string) (*Message, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, domain_id, envelope_from, envelope_to, subject, size_bytes,
		       received_at, expires_at, status, attempts, next_retry_at,
		       last_error, delivered_at, remote_addr, direction,
		       spam_score, spam_action, quarantined_at, quarantine_reason
		FROM queue WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("store: get message: %w", err)
	}
	defer rows.Close()

	msgs, err := scanMessages(rows)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, ErrNotFound
	}
	return msgs[0], nil
}

type ListFilter struct {
	Status      Status
	DomainID    int64
	DomainIDs   []int64
	Direction   Direction
	Limit       int
	Offset      int
	Quarantined int
}

func (db *DB) ListMessages(ctx context.Context, f ListFilter) ([]*Message, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	var args []any
	query := `
		SELECT id, domain_id, envelope_from, envelope_to, subject, size_bytes,
		       received_at, expires_at, status, attempts, next_retry_at,
		       last_error, delivered_at, remote_addr, direction,
		       spam_score, spam_action, quarantined_at, quarantine_reason
		FROM queue
		WHERE 1=1`

	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, string(f.Status))
	}
	if f.DomainID != 0 {
		query += ` AND domain_id = ?`
		args = append(args, f.DomainID)
	} else if len(f.DomainIDs) > 0 {
		placeholders := make([]string, len(f.DomainIDs))
		for i, id := range f.DomainIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		query += fmt.Sprintf(` AND domain_id IN (%s)`, strings.Join(placeholders, ","))
	} else if f.DomainIDs != nil {
		query += ` AND 1=0`
	}
	if f.Direction != "" {
		query += ` AND direction = ?`
		args = append(args, string(f.Direction))
	}
	if f.Quarantined == 1 {
		query += ` AND quarantined_at IS NOT NULL`
	} else if f.Quarantined == -1 {
		query += ` AND quarantined_at IS NULL`
	}
	query += ` ORDER BY received_at DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list messages: %w", err)
	}
	defer rows.Close()
	return scanMessages(rows)
}

func (db *DB) RetryNow(ctx context.Context, id string, now time.Time) error {
	return db.exec(ctx, `
		UPDATE queue SET status = 'queued', next_retry_at = ?
		WHERE id = ? AND status IN ('queued','failed','expired')`, formatTime(now), id)
}

func (db *DB) RetryDomainNow(ctx context.Context, domainID int64, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE queue SET next_retry_at = ?
		WHERE domain_id = ? AND status = 'queued' AND next_retry_at > ?`,
		formatTime(now), domainID, formatTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: retry domain: %w", err)
	}
	return res.RowsAffected()
}

func (db *DB) DeleteMessage(ctx context.Context, id string) error {
	return db.exec(ctx, `DELETE FROM queue WHERE id = ?`, id)
}

func (db *DB) PurgeDelivered(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `
		DELETE FROM queue
		WHERE status IN ('delivered','failed','expired') AND received_at <= ?`,
		formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge: %w", err)
	}
	return res.RowsAffected()
}

func (db *DB) exec(ctx context.Context, query string, args ...any) error {
	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store: exec: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanMessages(rows *sql.Rows) ([]*Message, error) {
	var out []*Message
	for rows.Next() {
		var (
			m           Message
			to          string
			received    string
			expires     string
			nextRetry   string
			status      string
			deliveredAt sql.NullString
			direction   string
			spamScore   sql.NullFloat64
			quarantined sql.NullString
		)
		if err := rows.Scan(&m.ID, &m.DomainID, &m.EnvelopeFrom, &to, &m.Subject,
			&m.SizeBytes, &received, &expires, &status, &m.Attempts,
			&nextRetry, &m.LastError, &deliveredAt, &m.RemoteAddr,
			&direction, &spamScore, &m.SpamAction,
			&quarantined, &m.QuarantineReason); err != nil {
			return nil, fmt.Errorf("store: scan message: %w", err)
		}
		var qErr error
		if m.QuarantinedAt, qErr = nullTime(quarantined); qErr != nil {
			return nil, qErr
		}
		m.Direction = Direction(direction)
		if spamScore.Valid {
			score := spamScore.Float64
			m.SpamScore = &score
		}
		if err := json.Unmarshal([]byte(to), &m.EnvelopeTo); err != nil {
			return nil, fmt.Errorf("store: unmarshal recipients for %s: %w", m.ID, err)
		}
		var err error
		if m.ReceivedAt, err = parseTime(received); err != nil {
			return nil, err
		}
		if m.ExpiresAt, err = parseTime(expires); err != nil {
			return nil, err
		}
		if m.NextRetryAt, err = parseTime(nextRetry); err != nil {
			return nil, err
		}
		if m.DeliveredAt, err = nullTime(deliveredAt); err != nil {
			return nil, err
		}
		m.Status = Status(status)
		out = append(out, &m)
	}
	return out, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
