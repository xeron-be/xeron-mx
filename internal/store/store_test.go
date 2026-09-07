package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newDomain(t *testing.T, db *DB, name string) int64 {
	t.Helper()
	id, err := db.CreateDomain(context.Background(), &Domain{
		Name:           name,
		PrimaryHost:    "mail." + name,
		PrimaryPort:    25,
		PrimaryTLS:     "starttls",
		RetentionHours: 168,
		Enabled:        true,
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return id
}

func enqueue(t *testing.T, db *DB, domainID int64, id string) {
	t.Helper()
	now := time.Now().UTC()
	err := db.Enqueue(context.Background(), &Message{
		ID:           id,
		DomainID:     domainID,
		EnvelopeFrom: "sender@example.net",
		EnvelopeTo:   []string{"someone@example.com"},
		Subject:      "test",
		SizeBytes:    1024,
		ReceivedAt:   now,
		ExpiresAt:    now.Add(7 * 24 * time.Hour),
		NextRetryAt:  now,
	})
	if err != nil {
		t.Fatalf("Enqueue(%s): %v", id, err)
	}
}

func markUp(t *testing.T, db *DB, domainID int64) {
	t.Helper()
	if _, _, err := db.RecordProbe(context.Background(), domainID, true, "", 3, 1, time.Now().UTC()); err != nil {
		t.Fatalf("RecordProbe: %v", err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	ctx := context.Background()

	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	id := newDomain(t, db, "example.com")
	db.Close()

	db2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	if _, err := db2.DomainByID(ctx, id); err != nil {
		t.Fatalf("domain lost across reopen: %v", err)
	}
}

func TestClaimBatchNeverHandsOutTheSameMessageTwice(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	markUp(t, db, domainID)

	const total = 60
	for i := 0; i < total; i++ {
		enqueue(t, db, domainID, fmt.Sprintf("msg%03d", i))
	}

	var (
		mu    sync.Mutex
		seen  = map[string]int{}
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for {
				batch, err := db.ClaimBatch(ctx, fmt.Sprintf("worker-%d", w), 5, time.Now().UTC())
				if err != nil {
					t.Errorf("ClaimBatch: %v", err)
					return
				}
				if len(batch) == 0 {
					return
				}
				mu.Lock()
				for _, m := range batch {
					seen[m.ID]++
				}
				mu.Unlock()
			}
		}(w)
	}
	close(start)
	wg.Wait()

	if len(seen) != total {
		t.Errorf("claimed %d distinct messages, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("message %s was claimed %d times, want exactly 1", id, n)
		}
	}
}

func TestClaimBatchSkipsDownAndDisabledDomains(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	down := newDomain(t, db, "down.example")
	up := newDomain(t, db, "up.example")
	disabled := newDomain(t, db, "disabled.example")

	markUp(t, db, up)
	markUp(t, db, disabled)

	d, err := db.DomainByID(ctx, disabled)
	if err != nil {
		t.Fatal(err)
	}
	d.Enabled = false
	if err := db.UpdateDomain(ctx, d); err != nil {
		t.Fatal(err)
	}

	enqueue(t, db, down, "aa")
	enqueue(t, db, up, "bb")
	enqueue(t, db, disabled, "cc")

	batch, err := db.ClaimBatch(ctx, "w1", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 1 || batch[0].ID != "bb" {
		got := make([]string, len(batch))
		for i, m := range batch {
			got[i] = m.ID
		}
		t.Fatalf("claimed %v, want only [bb]", got)
	}
}

func TestClaimBatchRespectsBackoff(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	markUp(t, db, domainID)
	enqueue(t, db, domainID, "aa")

	batch, err := db.ClaimBatch(ctx, "w1", 10, time.Now().UTC())
	if err != nil || len(batch) != 1 {
		t.Fatalf("first claim: %v, %d messages", err, len(batch))
	}

	if err := db.Reschedule(ctx, "aa", 1, "primary refused", time.Hour, 2*time.Hour, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	batch, err = db.ClaimBatch(ctx, "w1", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 0 {
		t.Fatalf("claimed %d messages that are still backing off, want 0", len(batch))
	}
}

func TestReleaseOrphanedClaims(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	markUp(t, db, domainID)
	enqueue(t, db, domainID, "aa")

	if _, err := db.ClaimBatch(ctx, "dead-worker", 10, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if batch, _ := db.ClaimBatch(ctx, "w2", 10, time.Now().UTC()); len(batch) != 0 {
		t.Fatal("a claimed message was handed out again before recovery")
	}

	n, err := db.ReleaseOrphanedClaims(ctx, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("released %d claims, want 1", n)
	}
	batch, err := db.ClaimBatch(ctx, "w2", 10, time.Now().UTC())
	if err != nil || len(batch) != 1 {
		t.Fatalf("recovered message not redeliverable: %v, %d messages", err, len(batch))
	}
}

func TestExpireOverdue(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")

	now := time.Now().UTC()
	if err := db.Enqueue(ctx, &Message{
		ID: "old", DomainID: domainID,
		EnvelopeFrom: "a@b.c", EnvelopeTo: []string{"d@example.com"},
		SizeBytes: 10, ReceivedAt: now.Add(-8 * 24 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), NextRetryAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	enqueue(t, db, domainID, "fresh")

	ids, err := db.ExpireOverdue(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "old" {
		t.Fatalf("expired %v, want [old]", ids)
	}
	m, err := db.GetMessage(ctx, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != StatusQueued {
		t.Fatalf("fresh message became %s, want queued", m.Status)
	}
}

func TestRecordProbeThresholds(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	now := time.Now().UTC()

	if _, up, _ := db.RecordProbe(ctx, domainID, true, "", 3, 2, now); up {
		t.Fatal("came up after a single success, want two")
	}
	if _, up, _ := db.RecordProbe(ctx, domainID, true, "", 3, 2, now); !up {
		t.Fatal("still down after two successes")
	}

	for i := 0; i < 2; i++ {
		if _, up, _ := db.RecordProbe(ctx, domainID, false, "timeout", 3, 2, now); !up {
			t.Fatalf("went down after %d failures, want 3", i+1)
		}
	}
	flipped, up, err := db.RecordProbe(ctx, domainID, false, "timeout", 3, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if up || !flipped {
		t.Fatal("did not go down after three consecutive failures")
	}

	st, err := db.PrimaryStatusFor(ctx, domainID)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastDown == nil {
		t.Fatal("last_down was not stamped on the transition")
	}
	if st.LastError != "timeout" {
		t.Fatalf("last_error = %q, want timeout", st.LastError)
	}
}

func TestRecordProbeResetsStreaks(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	now := time.Now().UTC()

	db.RecordProbe(ctx, domainID, true, "", 3, 3, now)
	db.RecordProbe(ctx, domainID, true, "", 3, 3, now)
	db.RecordProbe(ctx, domainID, false, "blip", 3, 3, now)

	st, err := db.PrimaryStatusFor(ctx, domainID)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConsecutiveSuccess != 0 {
		t.Fatalf("success streak = %d after a failure, want 0", st.ConsecutiveSuccess)
	}
	if st.IsUp {
		t.Fatal("flapping primary was declared up")
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	base, max := time.Minute, time.Hour

	var prev time.Duration
	for attempt := 1; attempt <= 6; attempt++ {
		d := Backoff(attempt, base, max)
		if d > max {
			t.Fatalf("attempt %d: backoff %v exceeds max %v", attempt, d, max)
		}

		if attempt > 1 && d < prev/4 {
			t.Fatalf("attempt %d: backoff %v collapsed from %v", attempt, d, prev)
		}
		prev = d
	}

	for i := 0; i < 50; i++ {
		d := Backoff(100, base, max)
		if d > max || d < max/2 {
			t.Fatalf("capped backoff %v outside [%v, %v]", d, max/2, max)
		}
	}
}

func TestBackoffIsJittered(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 100; i++ {
		seen[Backoff(5, time.Minute, time.Hour)] = true
	}
	if len(seen) < 50 {
		t.Fatalf("backoff produced %d distinct values in 100 calls, jitter is not working", len(seen))
	}
}

func TestStatsCountOnlyPending(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")

	enqueue(t, db, domainID, "aa")
	enqueue(t, db, domainID, "bb")
	if err := db.MarkDelivered(ctx, "aa", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	s, err := db.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Pending != 1 {
		t.Fatalf("pending = %d, want 1", s.Pending)
	}
	if s.Total != 2 {
		t.Fatalf("total = %d, want 2", s.Total)
	}
	if s.PendingBytes != 1024 {
		t.Fatalf("pending bytes = %d, want 1024", s.PendingBytes)
	}
}

func TestDomainNamesAreNormalized(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	newDomain(t, db, "Example.COM")

	for _, probe := range []string{"example.com", "EXAMPLE.COM", "Example.Com", "example.com."} {
		if _, err := db.DomainByName(ctx, probe); err != nil {
			t.Errorf("DomainByName(%q) failed: %v", probe, err)
		}
	}
}

func TestUnknownDomainIsNotFound(t *testing.T) {
	db := newDB(t)
	if _, err := db.DomainByName(context.Background(), "stranger.example"); err != ErrNotFound {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestEnvelopeRecipientsSurviveRoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")

	want := []string{"a@example.com", "b+tag@example.com", "c@example.com"}
	now := time.Now().UTC()
	if err := db.Enqueue(ctx, &Message{
		ID: "multi", DomainID: domainID,
		EnvelopeFrom: "",
		EnvelopeTo:   want,
		SizeBytes:    99, ReceivedAt: now, ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	m, err := db.GetMessage(ctx, "multi")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.EnvelopeTo) != len(want) {
		t.Fatalf("got %d recipients, want %d", len(m.EnvelopeTo), len(want))
	}
	for i := range want {
		if m.EnvelopeTo[i] != want[i] {
			t.Errorf("recipient %d = %q, want %q", i, m.EnvelopeTo[i], want[i])
		}
	}
	if m.EnvelopeFrom != "" {
		t.Errorf("null return path became %q", m.EnvelopeFrom)
	}
}

func TestFirstFailedProbeIsReported(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id := newDomain(t, db, "never-up.test")

	flipped, isUp, err := db.RecordProbe(ctx, id, false, "connection refused", 3, 2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !flipped {
		t.Fatal("the first failed probe was not reported, so nothing would ever alert")
	}
	if isUp {
		t.Fatal("the primary is reported up after a failed probe")
	}

	flipped, _, err = db.RecordProbe(ctx, id, false, "connection refused", 3, 2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if flipped {
		t.Fatal("a repeated failure was reported again; alerting would repeat on every probe")
	}
}
