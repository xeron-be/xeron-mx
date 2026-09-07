package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

//go:embed schema_v2.sql
var schemaV2SQL string

//go:embed schema_v3.sql
var schemaV3SQL string

//go:embed schema_v4.sql
var schemaV4SQL string

//go:embed schema_v5.sql
var schemaV5SQL string

//go:embed schema_v6.sql
var schemaV6SQL string

const schemaVersion = 6

type DB struct {
	*sql.DB
}

func Open(ctx context.Context, path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)

	// _txlock=immediate starts transactions as BEGIN IMMEDIATE to prevent SQLITE_BUSY_SNAPSHOT lock upgrades.
	dsn := path + "?_txlock=immediate" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(NORMAL)"

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}

	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	db := &DB{sqlDB}
	if err := db.migrate(ctx); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) migrate(ctx context.Context) error {
	var current int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("store: read user_version: %w", err)
	}
	if current == schemaVersion {
		return nil
	}
	if current > schemaVersion {
		return fmt.Errorf("store: database is schema v%d, this binary understands v%d: "+
			"downgrading is not supported", current, schemaVersion)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration: %w", err)
	}
	defer tx.Rollback()

	if current < 1 {
		if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
			return fmt.Errorf("store: apply schema v1: %w", err)
		}
	}
	if current < 2 {
		if _, err := tx.ExecContext(ctx, schemaV2SQL); err != nil {
			return fmt.Errorf("store: apply schema v2: %w", err)
		}
	}
	if current < 3 {
		if _, err := tx.ExecContext(ctx, schemaV3SQL); err != nil {
			return fmt.Errorf("store: apply schema v3: %w", err)
		}
	}
	if current < 4 {
		if _, err := tx.ExecContext(ctx, schemaV4SQL); err != nil {
			return fmt.Errorf("store: apply schema v4: %w", err)
		}
	}
	if current < 5 {
		if _, err := tx.ExecContext(ctx, schemaV5SQL); err != nil {
			return fmt.Errorf("store: apply schema v5: %w", err)
		}
	}
	if current < 6 {
		if _, err := tx.ExecContext(ctx, schemaV6SQL); err != nil {
			return fmt.Errorf("store: apply schema v6: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("store: set user_version: %w", err)
	}
	return tx.Commit()
}

func (db *DB) Snapshot(ctx context.Context, path string) error {
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("store: snapshot to %s: %w", path, err)
	}
	return nil
}

type Domain struct {
	ID               int64
	Name             string
	PrimaryHost      string
	PrimaryPort      int
	PrimaryTLS       string
	MaxQueueMessages *int64
	RetentionHours   int
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Message struct {
	ID           string
	DomainID     int64
	EnvelopeFrom string
	EnvelopeTo   []string
	Subject      string
	SizeBytes    int64
	ReceivedAt   time.Time
	ExpiresAt    time.Time
	Status       Status
	Attempts     int
	NextRetryAt  time.Time
	LastError    string
	DeliveredAt  *time.Time
	RemoteAddr   string

	Direction Direction

	SpamScore  *float64
	SpamAction string

	QuarantinedAt    *time.Time
	QuarantineReason string
}

type Direction string

const (
	DirectionInbound Direction = "inbound"

	DirectionOutbound Direction = "outbound"
)

type Status string

const (
	StatusQueued Status = "queued"

	StatusDelivering Status = "delivering"

	StatusDelivered Status = "delivered"

	StatusFailed Status = "failed"

	StatusExpired Status = "expired"
)

type PrimaryStatus struct {
	DomainID            int64
	IsUp                bool
	LastCheck           *time.Time
	LastUp              *time.Time
	LastDown            *time.Time
	ConsecutiveFailures int
	ConsecutiveSuccess  int
	LastError           string
}

const timeFmt = time.RFC3339Nano

func formatTime(t time.Time) string { return t.UTC().Format(timeFmt) }

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(timeFmt, s)
}

func nullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
