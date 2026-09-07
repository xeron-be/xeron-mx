package store

import (
	"context"
	"testing"
	"time"
)

func TestUserAllowedDomains(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	id, err := db.CreateUser(ctx, "operator@test.example", "hash", RoleOperator, []string{"xeron.be", "example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u, err := db.UserByID(ctx, id)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if u.Role != RoleOperator {
		t.Fatalf("expected role %q, got %q", RoleOperator, u.Role)
	}
	if len(u.AllowedDomains) != 2 || u.AllowedDomains[0] != "xeron.be" || u.AllowedDomains[1] != "example.com" {
		t.Fatalf("unexpected allowed domains: %+v", u.AllowedDomains)
	}
	if !u.CanAccessDomain("xeron.be") || !u.CanAccessDomain("XERON.BE") {
		t.Fatalf("expected access to xeron.be")
	}
	if !u.CanAccessDomain("example.com") {
		t.Fatalf("expected access to example.com")
	}
	if u.CanAccessDomain("other.com") {
		t.Fatalf("expected no access to other.com")
	}

	adminID, err := db.CreateUser(ctx, "admin@test.example", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := db.UserByID(ctx, adminID)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.CanAccessDomain("anything.test") {
		t.Fatal("admin should access any domain")
	}

	if err := db.UpdateUserScope(ctx, id, RoleViewer, []string{"onlyone.com"}); err != nil {
		t.Fatalf("UpdateUserScope: %v", err)
	}
	updated, err := db.UserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Role != RoleViewer || len(updated.AllowedDomains) != 1 || updated.AllowedDomains[0] != "onlyone.com" {
		t.Fatalf("unexpected updated user: %+v", updated)
	}
}

func TestFilterAndStatsForDomains(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	d1, err := db.CreateDomain(ctx, &Domain{Name: "domain1.test", PrimaryHost: "127.0.0.1", PrimaryPort: 25, PrimaryTLS: "opportunistic", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := db.CreateDomain(ctx, &Domain{Name: "domain2.test", PrimaryHost: "127.0.0.1", PrimaryPort: 25, PrimaryTLS: "opportunistic", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	err = db.Enqueue(ctx, &Message{
		ID: "msg-1", DomainID: d1, EnvelopeFrom: "a@domain1.test", EnvelopeTo: []string{"b@domain1.test"},
		SizeBytes: 100, ReceivedAt: now, ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = db.Enqueue(ctx, &Message{
		ID: "msg-2", DomainID: d2, EnvelopeFrom: "c@domain2.test", EnvelopeTo: []string{"d@domain2.test"},
		SizeBytes: 200, ReceivedAt: now, ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	msgsD1, err := db.ListMessages(ctx, ListFilter{DomainIDs: []int64{d1}})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgsD1) != 1 || msgsD1[0].ID != "msg-1" {
		t.Fatalf("expected msg-1, got %+v", msgsD1)
	}

	msgsD2, err := db.ListMessages(ctx, ListFilter{DomainIDs: []int64{d2}})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgsD2) != 1 || msgsD2[0].ID != "msg-2" {
		t.Fatalf("expected msg-2, got %+v", msgsD2)
	}

	statsD1, err := db.StatsForDomains(ctx, []int64{d1})
	if err != nil {
		t.Fatalf("StatsForDomains: %v", err)
	}
	if statsD1.Pending != 1 || statsD1.PendingBytes != 100 {
		t.Fatalf("unexpected stats for d1: %+v", statsD1)
	}

	statsBoth, err := db.StatsForDomains(ctx, []int64{d1, d2})
	if err != nil {
		t.Fatalf("StatsForDomains: %v", err)
	}
	if statsBoth.Pending != 2 || statsBoth.PendingBytes != 300 {
		t.Fatalf("unexpected stats for both: %+v", statsBoth)
	}
}
