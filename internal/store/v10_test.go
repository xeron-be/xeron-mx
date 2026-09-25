package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestAVersion9DatabaseUpgradesWithoutASendingLimit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v9.db")

	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{schemaSQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL,
		schemaV6SQL, schemaV7SQL, schemaV8SQL, schemaV9SQL} {
		if _, err := raw.ExecContext(ctx, script); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.ExecContext(ctx, `PRAGMA user_version = 9`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO domains (name, primary_host, primary_port, primary_tls, retention_hours, enabled, created_at, updated_at)
		VALUES ('old.example', 'mail.old.example', 25, 'opportunistic', 168, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade from v9: %v", err)
	}
	defer db.Close()

	d, err := db.DomainByName(ctx, "old.example")
	if err != nil {
		t.Fatalf("the domain did not survive the upgrade: %v", err)
	}
	if d.MonthlySendLimit != nil {
		t.Fatalf("an upgraded domain has a sending limit of %d; want none", *d.MonthlySendLimit)
	}
	if sent, err := db.SentThisMonth(ctx, d.ID, time.Now()); err != nil || sent != 0 {
		t.Fatalf("usage after the upgrade = %d, %v", sent, err)
	}
}
