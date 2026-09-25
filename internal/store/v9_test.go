package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestAVersion8DatabaseUpgradesWithItsAccounts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v8.db")

	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{schemaSQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL,
		schemaV6SQL, schemaV7SQL, schemaV8SQL} {
		if _, err := raw.ExecContext(ctx, script); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.ExecContext(ctx, `PRAGMA user_version = 8`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO users (email, password_hash, role, created_at) VALUES ('old@example.com', 'x', 'admin', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade from v8: %v", err)
	}
	defer db.Close()

	u, err := db.UserByEmail(ctx, "old@example.com")
	if err != nil {
		t.Fatalf("the account did not survive the upgrade: %v", err)
	}
	if u.TOTPEnabled || u.TOTPSecret != "" || u.TOTPLastStep != 0 {
		t.Fatalf("an upgraded account starts with a second factor: %+v", u)
	}
	if n, err := db.RecoveryCodesLeft(ctx, u.ID); err != nil || n != 0 {
		t.Fatalf("recovery codes table: %d, %v", n, err)
	}
}

func TestASecondFactorStepIsConsumedOnce(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id, err := db.CreateUser(ctx, "a@example.com", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := db.ConsumeTOTPStep(ctx, id, 100); ok {
		t.Fatal("a step was consumed before the second factor was enabled")
	}
	if err := db.EnableTOTP(ctx, id, 100, []string{"h1", "h2"}); err == nil {
		t.Fatal("enabled without a pending secret")
	}
	if err := db.SetPendingTOTP(ctx, id, "sealed"); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableTOTP(ctx, id, 100, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPendingTOTP(ctx, id, "another"); err == nil {
		t.Fatal("an enabled secret was replaced by a new setup")
	}

	for step, want := range map[int64]bool{100: false, 99: false} {
		if ok, _ := db.ConsumeTOTPStep(ctx, id, step); ok != want {
			t.Fatalf("step %d consumed = %v; want %v", step, ok, want)
		}
	}
	if ok, _ := db.ConsumeTOTPStep(ctx, id, 101); !ok {
		t.Fatal("the next step was refused")
	}
	if ok, _ := db.ConsumeTOTPStep(ctx, id, 101); ok {
		t.Fatal("the same step was consumed twice")
	}

	if ok, _ := db.ConsumeRecoveryCode(ctx, id, "h1"); !ok {
		t.Fatal("a recovery code was refused")
	}
	if ok, _ := db.ConsumeRecoveryCode(ctx, id, "h1"); ok {
		t.Fatal("a recovery code was used twice")
	}
	if n, _ := db.RecoveryCodesLeft(ctx, id); n != 1 {
		t.Fatalf("%d codes left; want 1", n)
	}

	if err := db.DisableTOTP(ctx, id); err != nil {
		t.Fatal(err)
	}
	u, _ := db.UserByID(ctx, id)
	if u.TOTPEnabled || u.TOTPSecret != "" {
		t.Fatal("disable left the second factor in place")
	}
	if n, _ := db.RecoveryCodesLeft(ctx, id); n != 0 {
		t.Fatal("disable left recovery codes behind")
	}
}

func TestOtherSessionsEndButThisOneStays(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id, err := db.CreateUser(ctx, "a@example.com", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"keep", "drop1", "drop2"} {
		if err := db.CreateSession(ctx, h, id, 3600e9, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.DeleteOtherSessions(ctx, id, "keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UserBySessionToken(ctx, "keep"); err != nil {
		t.Fatal("the kept session is gone")
	}
	for _, h := range []string{"drop1", "drop2"} {
		if _, err := db.UserBySessionToken(ctx, h); err == nil {
			t.Fatalf("session %s survived", h)
		}
	}
}
