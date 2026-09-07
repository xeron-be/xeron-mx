package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Webhook struct {
	ID            int64
	Name          string
	URL           string
	Secret        []byte
	Events        []string
	Enabled       bool
	CreatedAt     time.Time
	LastError     string
	LastSuccessAt *time.Time
}

func (w *Webhook) Wants(eventType string) bool {
	if !w.Enabled {
		return false
	}
	if len(w.Events) == 0 {
		return true
	}
	for _, e := range w.Events {
		if e == eventType {
			return true
		}
	}
	return false
}

const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

type Delivery struct {
	ID            int64
	WebhookID     int64
	WebhookName   string
	EventType     string
	Payload       string
	Status        string
	Attempts      int
	NextAttemptAt time.Time
	StatusCode    int
	LastError     string
	CreatedAt     time.Time
	DeliveredAt   *time.Time
}

func (db *DB) CreateWebhook(ctx context.Context, w *Webhook) (int64, error) {
	events, err := json.Marshal(nonNil(w.Events))
	if err != nil {
		return 0, fmt.Errorf("store: marshal webhook events: %w", err)
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO webhooks (name, url, secret, events, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(w.Name), strings.TrimSpace(w.URL), w.Secret,
		string(events), boolToInt(w.Enabled), formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: create webhook: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) UpdateWebhook(ctx context.Context, w *Webhook) error {
	events, err := json.Marshal(nonNil(w.Events))
	if err != nil {
		return fmt.Errorf("store: marshal webhook events: %w", err)
	}
	return db.exec(ctx, `
		UPDATE webhooks SET name = ?, url = ?, events = ?, enabled = ? WHERE id = ?`,
		strings.TrimSpace(w.Name), strings.TrimSpace(w.URL), string(events),
		boolToInt(w.Enabled), w.ID)
}

func (db *DB) SetWebhookSecret(ctx context.Context, id int64, secret []byte) error {
	return db.exec(ctx, `UPDATE webhooks SET secret = ? WHERE id = ?`, secret, id)
}

func (db *DB) DeleteWebhook(ctx context.Context, id int64) error {
	return db.exec(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
}

func (db *DB) Webhook(ctx context.Context, id int64) (*Webhook, error) {
	w, err := scanWebhook(db.QueryRowContext(ctx, webhookCols+` WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return w, err
}

func (db *DB) ListWebhooks(ctx context.Context) ([]*Webhook, error) {
	rows, err := db.QueryContext(ctx, webhookCols+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list webhooks: %w", err)
	}
	defer rows.Close()

	var out []*Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

const webhookCols = `
	SELECT id, name, url, secret, events, enabled, created_at, last_error, last_success_at
	FROM webhooks`

func scanWebhook(row rowScanner) (*Webhook, error) {
	var (
		w         Webhook
		secret    []byte
		events    string
		enabled   int
		created   string
		lastOK    sql.NullString
		lastError string
	)
	err := row.Scan(&w.ID, &w.Name, &w.URL, &secret, &events, &enabled, &created, &lastError, &lastOK)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan webhook: %w", err)
	}
	w.Secret = secret
	w.Enabled = enabled != 0
	w.LastError = lastError
	if err := json.Unmarshal([]byte(events), &w.Events); err != nil {
		w.Events = nil
	}
	if w.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if w.LastSuccessAt, err = nullTime(lastOK); err != nil {
		return nil, err
	}
	return &w, nil
}

func (db *DB) EnqueueDelivery(ctx context.Context, webhookID int64, eventType, payload string, at time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `
		INSERT INTO webhook_deliveries
			(webhook_id, event_type, payload, status, attempts, next_attempt_at, created_at)
		VALUES (?, ?, ?, 'pending', 0, ?, ?)`,
		webhookID, eventType, payload, formatTime(at), formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: enqueue delivery: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) DueDeliveries(ctx context.Context, now time.Time, limit int) ([]*Delivery, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.QueryContext(ctx, deliveryCols+`
		WHERE d.status = 'pending' AND d.next_attempt_at <= ?
		ORDER BY d.next_attempt_at LIMIT ?`, formatTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: due deliveries: %w", err)
	}
	defer rows.Close()
	return scanDeliveries(rows)
}

func (db *DB) ListDeliveries(ctx context.Context, webhookID int64, limit int) ([]*Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	query := deliveryCols
	args := []any{}
	if webhookID > 0 {
		query += ` WHERE d.webhook_id = ?`
		args = append(args, webhookID)
	}
	query += ` ORDER BY d.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list deliveries: %w", err)
	}
	defer rows.Close()
	return scanDeliveries(rows)
}

const deliveryCols = `
	SELECT d.id, d.webhook_id, COALESCE(w.name, ''), d.event_type, d.payload, d.status,
	       d.attempts, d.next_attempt_at, d.status_code, d.last_error, d.created_at, d.delivered_at
	FROM webhook_deliveries d
	LEFT JOIN webhooks w ON w.id = d.webhook_id`

func scanDeliveries(rows *sql.Rows) ([]*Delivery, error) {
	var out []*Delivery
	for rows.Next() {
		var (
			d         Delivery
			next      string
			created   string
			delivered sql.NullString
		)
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.WebhookName, &d.EventType, &d.Payload,
			&d.Status, &d.Attempts, &next, &d.StatusCode, &d.LastError, &created, &delivered); err != nil {
			return nil, fmt.Errorf("store: scan delivery: %w", err)
		}
		var err error
		if d.NextAttemptAt, err = parseTime(next); err != nil {
			return nil, err
		}
		if d.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if d.DeliveredAt, err = nullTime(delivered); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, rows.Err()
}

func (db *DB) MarkDeliverySucceeded(ctx context.Context, id int64, statusCode int) error {
	now := formatTime(time.Now().UTC())
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin delivery success: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET status = 'delivered', attempts = attempts + 1, status_code = ?,
		    last_error = '', delivered_at = ?
		WHERE id = ?`, statusCode, now, id); err != nil {
		return fmt.Errorf("store: mark delivery delivered: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE webhooks SET last_success_at = ?, last_error = ''
		WHERE id = (SELECT webhook_id FROM webhook_deliveries WHERE id = ?)`, now, id); err != nil {
		return fmt.Errorf("store: touch webhook: %w", err)
	}
	return tx.Commit()
}

func (db *DB) RescheduleDelivery(ctx context.Context, id int64, statusCode int, reason string, next time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin delivery retry: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET attempts = attempts + 1, status_code = ?, last_error = ?, next_attempt_at = ?
		WHERE id = ?`, statusCode, truncate(reason, 500), formatTime(next), id); err != nil {
		return fmt.Errorf("store: reschedule delivery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE webhooks SET last_error = ?
		WHERE id = (SELECT webhook_id FROM webhook_deliveries WHERE id = ?)`,
		truncate(reason, 500), id); err != nil {
		return fmt.Errorf("store: touch webhook: %w", err)
	}
	return tx.Commit()
}

func (db *DB) MarkDeliveryFailed(ctx context.Context, id int64, statusCode int, reason string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin delivery failure: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET status = 'failed', attempts = attempts + 1, status_code = ?, last_error = ?
		WHERE id = ?`, statusCode, truncate(reason, 500), id); err != nil {
		return fmt.Errorf("store: mark delivery failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE webhooks SET last_error = ?
		WHERE id = (SELECT webhook_id FROM webhook_deliveries WHERE id = ?)`,
		truncate(reason, 500), id); err != nil {
		return fmt.Errorf("store: touch webhook: %w", err)
	}
	return tx.Commit()
}

func (db *DB) PurgeDeliveries(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `
		DELETE FROM webhook_deliveries
		WHERE status != 'pending' AND created_at < ?`, formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge deliveries: %w", err)
	}
	return res.RowsAffected()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
