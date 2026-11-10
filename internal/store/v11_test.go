package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAVersion10DatabaseUpgradesWithNoSESIdentities(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v10.db")

	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{schemaSQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL,
		schemaV6SQL, schemaV7SQL, schemaV8SQL, schemaV9SQL, schemaV10SQL} {
		if _, err := raw.ExecContext(ctx, script); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.ExecContext(ctx, `PRAGMA user_version = 10`); err != nil {
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
		t.Fatalf("upgrade from v10: %v", err)
	}
	defer db.Close()

	d, err := db.DomainByName(ctx, "old.example")
	if err != nil {
		t.Fatalf("the domain did not survive the upgrade: %v", err)
	}
	if _, err := db.SESIdentityFor(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an upgraded domain already has an SES identity: %v", err)
	}
}

func TestSESIdentityRoundTripAndCascade(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	parent := newDomain(t, db, "xeron.test")
	child := newDomain(t, db, "client.xeron.test")
	now := time.Now().UTC().Truncate(time.Second)

	if err := db.SaveSESIdentity(ctx, &SESIdentity{
		DomainID: parent, Identity: "xeron.test", Managed: true, Status: SESPending,
		DKIMTokens: []string{"a", "b", "c"}, CheckedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSESIdentity(ctx, &SESIdentity{
		DomainID: child, Identity: "xeron.test", Inherited: true, Status: SESPending,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.SESIdentityFor(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Managed || got.Inherited || len(got.DKIMTokens) != 3 || got.CheckedAt == nil || !got.CheckedAt.Equal(now) {
		t.Fatalf("round trip = %+v", got)
	}

	got.Status = SESVerified
	got.LastError = ""
	if err := db.SaveSESIdentity(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := db.SESIdentityFor(ctx, parent); again.Status != SESVerified || !again.CreatedAt.Equal(got.CreatedAt) {
		t.Fatalf("update = %+v", again)
	}

	deps, err := db.SESDependents(ctx, "xeron.test", parent)
	if err != nil || len(deps) != 1 || deps[0] != "client.xeron.test" {
		t.Fatalf("dependents = %v, %v", deps, err)
	}

	if err := db.DeleteDomain(ctx, child); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SESIdentityFor(ctx, child); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the row outlived its domain: %v", err)
	}
	if all, _ := db.ListSESIdentities(ctx); len(all) != 1 {
		t.Fatalf("list = %d rows", len(all))
	}
}
