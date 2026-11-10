package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestAVersion11DatabaseUpgradesWithEveryDomainSending(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v11.db")
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{schemaSQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL,
		schemaV6SQL, schemaV7SQL, schemaV8SQL, schemaV9SQL, schemaV10SQL, schemaV11SQL} {
		if _, err := raw.ExecContext(ctx, script); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.ExecContext(ctx, `PRAGMA user_version = 11`); err != nil {
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
		t.Fatalf("upgrade from v11: %v", err)
	}
	defer db.Close()
	d, err := db.DomainByName(ctx, "old.example")
	if err != nil {
		t.Fatal(err)
	}
	st, err := db.SendingStateFor(ctx, d.ID)
	if err != nil || st.Suspended() {
		t.Fatalf("an upgraded domain is suspended: %+v, %v", st, err)
	}
}

func TestSendingCountersAndState(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id := newDomain(t, db, "client.test")
	now := time.Now().UTC()

	db.RecordSent(ctx, id, 3, now)
	db.RecordSent(ctx, id, 2, now)
	db.RecordSent(ctx, id, 50, now.Add(-10*24*time.Hour))

	for i, at := range []time.Time{now, now, now.Add(-10 * 24 * time.Hour)} {
		added, err := db.AddFeedback(ctx, &SendingFeedback{
			DomainID: id, Kind: FeedbackBounce, Sender: "a@client.test",
			Recipient: "x@far.test", FeedbackID: []string{"f1", "f1", "f2"}[i], OccurredAt: at,
		})
		if err != nil {
			t.Fatal(err)
		}
		if added != (i != 1) {
			t.Fatalf("feedback %d added = %v; want the duplicate refused", i, added)
		}
	}
	db.AddFeedback(ctx, &SendingFeedback{DomainID: id, Kind: FeedbackComplaint, Sender: "a@client.test",
		Recipient: "y@far.test", FeedbackID: "c1", OccurredAt: now})

	w, err := db.SendingStats(ctx, id, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if w.Sent != 5 || w.Bounces != 1 || w.Complaints != 1 {
		t.Fatalf("window = %+v; want 5 sent, 1 bounce, 1 complaint", w)
	}
	if list, _ := db.RecentFeedback(ctx, id, 10); len(list) != 3 || list[0].OccurredAt.IsZero() {
		t.Fatalf("recent = %d entries", len(list))
	}

	if ok, _ := db.SuspendSending(ctx, id, "bounces", "auto", now); !ok {
		t.Fatal("first suspension not reported")
	}
	if ok, _ := db.SuspendSending(ctx, id, "manual", "admin", now); ok {
		t.Fatal("a second suspension overwrote the first")
	}
	st, _ := db.SendingStateFor(ctx, id)
	if !st.Suspended() || st.SuspendedReason != "bounces" {
		t.Fatalf("state = %+v", st)
	}
	if ok, _ := db.ResumeSending(ctx, id, now); !ok {
		t.Fatal("resume not reported")
	}
	if ok, _ := db.ResumeSending(ctx, id, now); ok {
		t.Fatal("resuming a running domain reported a change")
	}
	st, _ = db.SendingStateFor(ctx, id)
	if st.Suspended() || st.CountedSince == nil {
		t.Fatalf("after resume: %+v", st)
	}

	if err := db.PruneSending(ctx, now.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if list, _ := db.RecentFeedback(ctx, id, 10); len(list) != 2 {
		t.Fatalf("after prune: %d entries; want the old one gone", len(list))
	}
}
