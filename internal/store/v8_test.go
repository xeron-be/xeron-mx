package store

import (
	"context"
	"testing"
	"time"
)

func TestTheMalwareScanOutcomeTravelsWithTheMessage(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	now := time.Now().UTC()

	err := db.Enqueue(ctx, &Message{
		ID: "scan1", DomainID: domainID, EnvelopeFrom: "a@sender.test",
		EnvelopeTo: []string{"b@example.com"}, SizeBytes: 1, ReceivedAt: now,
		ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
		MalwareScan: "skipped: larger than 26214400 bytes",
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := db.GetMessage(ctx, "scan1")
	if err != nil {
		t.Fatal(err)
	}
	if m.MalwareScan != "skipped: larger than 26214400 bytes" {
		t.Fatalf("read back %q", m.MalwareScan)
	}

	enqueue(t, db, domainID, "scan2")
	if m, err := db.GetMessage(ctx, "scan2"); err != nil || m.MalwareScan != "" {
		t.Fatalf("a message never scanned reads back %q, %v; want empty", m.MalwareScan, err)
	}
}
