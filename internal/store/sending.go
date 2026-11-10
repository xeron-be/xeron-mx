package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Sending reputation timestamps use a fixed-width format so that they compare
// correctly as strings in SQL (RFC3339Nano drops trailing zeros, and "…00Z"
// would then sort after "…00.5Z").
const (
	sendingTimeFmt = "2006-01-02T15:04:05Z"
	sendingHourFmt = "2006-01-02T15"
)

func sendingTime(t time.Time) string { return t.UTC().Format(sendingTimeFmt) }

const (
	FeedbackBounce    = "bounce"
	FeedbackComplaint = "complaint"
)

type SendingFeedback struct {
	ID           int64
	DomainID     int64
	Kind         string
	Sender       string
	Recipient    string
	FeedbackID   string
	SESMessageID string
	Detail       string
	OccurredAt   time.Time
}

// SendingWindow is what a domain sent through SES, and what came back, since
// a point in time.
type SendingWindow struct {
	Since      time.Time
	Sent       int64
	Bounces    int64
	Complaints int64
}

type SendingState struct {
	DomainID        int64
	SuspendedAt     *time.Time
	SuspendedReason string
	SuspendedBy     string
	WarnedAt        *time.Time
	// CountedSince is when an admin last lifted a suspension: feedback before
	// it no longer counts, or the domain would be suspended again at once.
	CountedSince *time.Time
}

func (s *SendingState) Suspended() bool { return s != nil && s.SuspendedAt != nil }

// RecordSent adds n recipients handed to SES for the domain, in the hour of at.
func (db *DB) RecordSent(ctx context.Context, domainID int64, n int, at time.Time) error {
	if n <= 0 {
		return nil
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO sending_stats (domain_id, hour, sent) VALUES (?, ?, ?)
		ON CONFLICT(domain_id, hour) DO UPDATE SET sent = sent + excluded.sent`,
		domainID, at.UTC().Format(sendingHourFmt), n)
	if err != nil {
		return fmt.Errorf("store: record sent: %w", err)
	}
	return nil
}

// AddFeedback records one bounce or complaint, once: SQS delivers at least
// once, so the same event can arrive twice. It reports whether it was new.
func (db *DB) AddFeedback(ctx context.Context, f *SendingFeedback) (bool, error) {
	res, err := db.ExecContext(ctx, `
		INSERT OR IGNORE INTO sending_feedback
			(domain_id, kind, sender, recipient, feedback_id, ses_message_id, detail, occurred_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.DomainID, f.Kind, f.Sender, f.Recipient, f.FeedbackID, f.SESMessageID, f.Detail,
		sendingTime(f.OccurredAt), sendingTime(time.Now()))
	if err != nil {
		return false, fmt.Errorf("store: add feedback: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (db *DB) SendingStats(ctx context.Context, domainID int64, since time.Time) (*SendingWindow, error) {
	w := &SendingWindow{Since: since.UTC()}
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(sent), 0) FROM sending_stats WHERE domain_id = ? AND hour >= ?`,
		domainID, since.UTC().Format(sendingHourFmt)).Scan(&w.Sent)
	if err != nil {
		return nil, fmt.Errorf("store: sending stats: %w", err)
	}
	err = db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN kind = 'bounce' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN kind = 'complaint' THEN 1 ELSE 0 END), 0)
		FROM sending_feedback WHERE domain_id = ? AND occurred_at >= ?`,
		domainID, sendingTime(since)).Scan(&w.Bounces, &w.Complaints)
	if err != nil {
		return nil, fmt.Errorf("store: sending feedback stats: %w", err)
	}
	return w, nil
}

func (db *DB) RecentFeedback(ctx context.Context, domainID int64, limit int) ([]*SendingFeedback, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, domain_id, kind, sender, recipient, feedback_id, ses_message_id, detail, occurred_at
		FROM sending_feedback WHERE domain_id = ? ORDER BY occurred_at DESC, id DESC LIMIT ?`,
		domainID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent feedback: %w", err)
	}
	defer rows.Close()
	var out []*SendingFeedback
	for rows.Next() {
		var (
			f  SendingFeedback
			at string
		)
		if err := rows.Scan(&f.ID, &f.DomainID, &f.Kind, &f.Sender, &f.Recipient, &f.FeedbackID,
			&f.SESMessageID, &f.Detail, &at); err != nil {
			return nil, fmt.Errorf("store: scan feedback: %w", err)
		}
		f.OccurredAt, _ = time.Parse(sendingTimeFmt, at)
		out = append(out, &f)
	}
	return out, rows.Err()
}

func (db *DB) SendingStateFor(ctx context.Context, domainID int64) (*SendingState, error) {
	var (
		st                         = SendingState{DomainID: domainID}
		suspended, warned, counted sql.NullString
	)
	err := db.QueryRowContext(ctx, `
		SELECT suspended_at, suspended_reason, suspended_by, warned_at, counted_since
		FROM sending_state WHERE domain_id = ?`, domainID).
		Scan(&suspended, &st.SuspendedReason, &st.SuspendedBy, &warned, &counted)
	if err == sql.ErrNoRows {
		return &st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: sending state: %w", err)
	}
	st.SuspendedAt = sendingNullTime(suspended)
	st.WarnedAt = sendingNullTime(warned)
	st.CountedSince = sendingNullTime(counted)
	return &st, nil
}

// SuspendSending stops the domain's submissions. It reports whether the domain
// was not already suspended, so that the event and the alert fire once.
func (db *DB) SuspendSending(ctx context.Context, domainID int64, reason, by string, at time.Time) (bool, error) {
	res, err := db.ExecContext(ctx, `
		INSERT INTO sending_state (domain_id, suspended_at, suspended_reason, suspended_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(domain_id) DO UPDATE SET
			suspended_at = excluded.suspended_at,
			suspended_reason = excluded.suspended_reason,
			suspended_by = excluded.suspended_by
		WHERE sending_state.suspended_at IS NULL`,
		domainID, sendingTime(at), reason, by)
	if err != nil {
		return false, fmt.Errorf("store: suspend sending: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ResumeSending lifts a suspension and starts counting afresh from at.
func (db *DB) ResumeSending(ctx context.Context, domainID int64, at time.Time) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE sending_state
		SET suspended_at = NULL, suspended_reason = '', suspended_by = '', warned_at = NULL, counted_since = ?
		WHERE domain_id = ? AND suspended_at IS NOT NULL`,
		sendingTime(at), domainID)
	if err != nil {
		return false, fmt.Errorf("store: resume sending: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// MarkSendingWarned records that the warning was given, so it is given once
// per window rather than on every event.
func (db *DB) MarkSendingWarned(ctx context.Context, domainID int64, at time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO sending_state (domain_id, warned_at) VALUES (?, ?)
		ON CONFLICT(domain_id) DO UPDATE SET warned_at = excluded.warned_at`,
		domainID, sendingTime(at))
	if err != nil {
		return fmt.Errorf("store: mark warned: %w", err)
	}
	return nil
}

// PruneSending forgets what is older than every window could look at.
func (db *DB) PruneSending(ctx context.Context, before time.Time) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sending_stats WHERE hour < ?`,
		before.UTC().Format(sendingHourFmt)); err != nil {
		return fmt.Errorf("store: prune sending stats: %w", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM sending_feedback WHERE occurred_at < ?`,
		sendingTime(before)); err != nil {
		return fmt.Errorf("store: prune feedback: %w", err)
	}
	return nil
}

func sendingNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(sendingTimeFmt, ns.String)
	if err != nil {
		return nil
	}
	return &t
}
