package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (db *DB) CreateDomain(ctx context.Context, d *Domain) (int64, error) {
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin create domain: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO domains (name, primary_host, primary_port, primary_tls,
		                     max_queue_messages, retention_hours, enabled,
		                     created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalizeDomain(d.Name), d.PrimaryHost, d.PrimaryPort, d.PrimaryTLS,
		d.MaxQueueMessages, d.RetentionHours, boolToInt(d.Enabled),
		formatTime(now), formatTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: create domain: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO primary_status (domain_id, is_up) VALUES (?, 0)`, id); err != nil {
		return 0, fmt.Errorf("store: seed primary status: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) DomainByName(ctx context.Context, name string) (*Domain, error) {
	return db.scanDomain(db.QueryRowContext(ctx, domainCols+` WHERE name = ?`, normalizeDomain(name)))
}

func (db *DB) DomainByID(ctx context.Context, id int64) (*Domain, error) {
	return db.scanDomain(db.QueryRowContext(ctx, domainCols+` WHERE id = ?`, id))
}

func (db *DB) ListDomains(ctx context.Context) ([]*Domain, error) {
	rows, err := db.QueryContext(ctx, domainCols+` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list domains: %w", err)
	}
	defer rows.Close()

	var out []*Domain
	for rows.Next() {
		d, err := scanDomainRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (db *DB) UpdateDomain(ctx context.Context, d *Domain) error {
	return db.exec(ctx, `
		UPDATE domains
		SET primary_host = ?, primary_port = ?, primary_tls = ?,
		    max_queue_messages = ?, retention_hours = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		d.PrimaryHost, d.PrimaryPort, d.PrimaryTLS, d.MaxQueueMessages,
		d.RetentionHours, boolToInt(d.Enabled), formatTime(time.Now().UTC()), d.ID)
}

func (db *DB) DeleteDomain(ctx context.Context, id int64) error {
	return db.exec(ctx, `DELETE FROM domains WHERE id = ?`, id)
}

const domainCols = `
	SELECT id, name, primary_host, primary_port, primary_tls,
	       max_queue_messages, retention_hours, enabled, created_at, updated_at
	FROM domains`

type rowScanner interface {
	Scan(dest ...any) error
}

func (db *DB) scanDomain(row rowScanner) (*Domain, error) {
	d, err := scanDomainRow(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return d, err
}

func scanDomainRow(row rowScanner) (*Domain, error) {
	var (
		d        Domain
		maxQueue sql.NullInt64
		enabled  int
		created  string
		updated  string
	)
	if err := row.Scan(&d.ID, &d.Name, &d.PrimaryHost, &d.PrimaryPort, &d.PrimaryTLS,
		&maxQueue, &d.RetentionHours, &enabled, &created, &updated); err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("store: scan domain: %w", err)
	}
	if maxQueue.Valid {
		d.MaxQueueMessages = &maxQueue.Int64
	}
	d.Enabled = enabled != 0
	var err error
	if d.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if d.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	return &d, nil
}

func (db *DB) RecordProbe(ctx context.Context, domainID int64, ok bool, probeErr string, failureThreshold, successThreshold int, now time.Time) (flipped bool, isUp bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, fmt.Errorf("store: begin probe: %w", err)
	}
	defer tx.Rollback()

	var (
		wasUp       int
		failures    int
		success     int
		neverProbed int
	)
	err = tx.QueryRowContext(ctx, `
		SELECT is_up, consecutive_failures, consecutive_success, last_check IS NULL
		FROM primary_status WHERE domain_id = ?`, domainID).
		Scan(&wasUp, &failures, &success, &neverProbed)
	if err == sql.ErrNoRows {
		return false, false, ErrNotFound
	}
	if err != nil {
		return false, false, fmt.Errorf("store: read probe state: %w", err)
	}

	isUp = wasUp != 0
	if ok {
		success++
		failures = 0
		if !isUp && success >= successThreshold {
			isUp, flipped = true, true
		}
	} else {
		failures++
		success = 0
		switch {
		case isUp && failures >= failureThreshold:
			isUp, flipped = false, true
		case neverProbed != 0:
			flipped = true
		}
	}

	set := `is_up = ?, last_check = ?, consecutive_failures = ?, consecutive_success = ?, last_error = ?`
	args := []any{boolToInt(isUp), formatTime(now), failures, success, truncate(probeErr, 500)}
	if flipped {
		if isUp {
			set += `, last_up = ?`
		} else {
			set += `, last_down = ?`
		}
		args = append(args, formatTime(now))
	}
	args = append(args, domainID)

	if _, err := tx.ExecContext(ctx,
		`UPDATE primary_status SET `+set+` WHERE domain_id = ?`, args...); err != nil {
		return false, false, fmt.Errorf("store: update probe state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, false, err
	}
	return flipped, isUp, nil
}

func (db *DB) PrimaryStatusFor(ctx context.Context, domainID int64) (*PrimaryStatus, error) {
	var (
		s                           PrimaryStatus
		isUp                        int
		lastCheck, lastUp, lastDown sql.NullString
	)
	err := db.QueryRowContext(ctx, `
		SELECT domain_id, is_up, last_check, last_up, last_down,
		       consecutive_failures, consecutive_success, last_error
		FROM primary_status WHERE domain_id = ?`, domainID).
		Scan(&s.DomainID, &isUp, &lastCheck, &lastUp, &lastDown,
			&s.ConsecutiveFailures, &s.ConsecutiveSuccess, &s.LastError)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: primary status: %w", err)
	}
	s.IsUp = isUp != 0
	if s.LastCheck, err = nullTime(lastCheck); err != nil {
		return nil, err
	}
	if s.LastUp, err = nullTime(lastUp); err != nil {
		return nil, err
	}
	if s.LastDown, err = nullTime(lastDown); err != nil {
		return nil, err
	}
	return &s, nil
}

const (
	EventMailReceived     = "mail_received"
	EventMailDelivered    = "mail_delivered"
	EventMailDeferred     = "mail_deferred"
	EventMailFailed       = "mail_failed"
	EventMailExpired      = "mail_expired"
	EventMailRejected     = "mail_rejected"
	EventMailQuarantined  = "mail_quarantined"
	EventPrimaryUp        = "primary_up"
	EventPrimaryDown      = "primary_down"
	EventQueueFull        = "queue_full"
	EventAdminRead        = "admin_read_message"
	EventAdminDelete      = "admin_delete_message"
	EventAdminRetry       = "admin_retry_message"
	EventLogin            = "login"
	EventLoginFailed      = "login_failed"
	EventStartup          = "startup"
	EventMaintenanceDrain = "maintenance_drain"
)

type Event struct {
	ID        int64          `json:"id"`
	Type      string         `json:"type"`
	DomainID  *int64         `json:"domain_id,omitempty"`
	QueueID   *string        `json:"queue_id,omitempty"`
	UserID    *int64         `json:"user_id,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	CreatedAt time.Time      `json:"created_at"`

	User       string `json:"user,omitempty"`
	DomainName string `json:"domain_name,omitempty"`
}

func (db *DB) RecordEvent(ctx context.Context, e *Event) error {
	data := "{}"
	if e.Data != nil {
		raw, err := json.Marshal(e.Data)
		if err != nil {
			return fmt.Errorf("store: marshal event data: %w", err)
		}
		data = string(raw)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO events (type, domain_id, queue_id, user_id, data, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		e.Type, e.DomainID, e.QueueID, e.UserID, data, formatTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("store: record event: %w", err)
	}
	return nil
}

func (db *DB) ListEvents(ctx context.Context, limit int) ([]*Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, type, domain_id, queue_id, user_id, data, created_at
		FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list events: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (db *DB) ListEventsForDomains(ctx context.Context, domainIDs []int64, limit int) ([]*Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if len(domainIDs) == 0 {
		return []*Event{}, nil
	}
	placeholders := make([]string, len(domainIDs))
	args := make([]any, len(domainIDs))
	for i, id := range domainIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT id, type, domain_id, queue_id, user_id, data, created_at
		FROM events
		WHERE domain_id IN (%s)
		ORDER BY id DESC LIMIT ?`, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list events for domains: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]*Event, error) {
	var out []*Event
	for rows.Next() {
		var (
			e        Event
			domainID sql.NullInt64
			queueID  sql.NullString
			userID   sql.NullInt64
			data     string
			created  string
		)
		if err := rows.Scan(&e.ID, &e.Type, &domainID, &queueID, &userID, &data, &created); err != nil {
			return nil, fmt.Errorf("store: scan event: %w", err)
		}
		if domainID.Valid {
			e.DomainID = &domainID.Int64
		}
		if queueID.Valid {
			e.QueueID = &queueID.String
		}
		if userID.Valid {
			e.UserID = &userID.Int64
		}
		if err := json.Unmarshal([]byte(data), &e.Data); err != nil {
			e.Data = map[string]any{}
		}
		var err error
		if e.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (db *DB) PurgeEvents(ctx context.Context, keep int64) (int64, error) {
	res, err := db.ExecContext(ctx, `
		DELETE FROM events WHERE id <= (
			SELECT COALESCE(MIN(id), 0) FROM (
				SELECT id FROM events ORDER BY id DESC LIMIT ?
			)
		) - 1`, keep)
	if err != nil {
		return 0, fmt.Errorf("store: purge events: %w", err)
	}
	return res.RowsAffected()
}

func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const (
	EventDomainAdded    = "domain_added"
	EventDomainDeleted  = "domain_deleted"
	EventMailReleased   = "mail_released"
	EventFilterCreated  = "filter_created"
	EventFilterDeleted  = "filter_deleted"
	EventDKIMCreated    = "dkim_key_created"
	EventDKIMDeleted    = "dkim_key_deleted"
	EventRouteCreated   = "route_created"
	EventRouteDeleted   = "route_deleted"
	EventSMTPUserAdded  = "smtp_user_created"
	EventSMTPUserGone   = "smtp_user_deleted"
	EventConfigImported = "config_imported"
	EventTokenCreated   = "api_token_created"
	EventTokenDeleted   = "api_token_deleted"
	EventWebhookCreated = "webhook_created"
	EventWebhookUpdated = "webhook_updated"
	EventWebhookDeleted = "webhook_deleted"
	EventClusterSynced  = "cluster_config_synced"
)

type EventCategory struct {
	Name  string   `json:"name"`
	Types []string `json:"types"`
}

func EventCatalogue() []EventCategory {
	return []EventCategory{
		{Name: "mail", Types: []string{
			EventMailReceived, EventMailDelivered, EventMailDeferred,
			EventMailFailed, EventMailExpired, EventMailRejected,
			EventMailQuarantined, EventMailReleased,
		}},
		{Name: "health", Types: []string{
			EventPrimaryUp, EventPrimaryDown, EventQueueFull, EventStartup,
		}},
		{Name: "admin", Types: []string{
			EventLogin, EventLoginFailed, EventAdminRead, EventAdminDelete,
			EventAdminRetry, EventDomainAdded, EventDomainDeleted,
			EventSMTPUserAdded, EventSMTPUserGone, EventFilterCreated,
			EventFilterDeleted, EventDKIMCreated, EventDKIMDeleted,
			EventRouteCreated, EventRouteDeleted, EventConfigImported,
			EventTokenCreated, EventTokenDeleted, EventWebhookCreated,
			EventWebhookUpdated, EventWebhookDeleted, EventClusterSynced,
		}},
	}
}

func KnownEventType(t string) bool {
	for _, cat := range EventCatalogue() {
		for _, known := range cat.Types {
			if known == t {
				return true
			}
		}
	}
	return false
}
