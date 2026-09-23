package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestAuthenticationResultsTravelWithTheMessage(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	now := time.Now().UTC()

	err := db.Enqueue(ctx, &Message{
		ID: "auth1", DomainID: domainID, EnvelopeFrom: "a@sender.test",
		EnvelopeTo: []string{"b@example.com"}, SizeBytes: 1, ReceivedAt: now,
		ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
		AuthResults:         "spf=pass smtp.mailfrom=sender.test; dkim=none",
		SenderAuthenticated: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	m, err := db.GetMessage(ctx, "auth1")
	if err != nil {
		t.Fatal(err)
	}
	if m.AuthResults != "spf=pass smtp.mailfrom=sender.test; dkim=none" || !m.SenderAuthenticated {
		t.Fatalf("read back %q, authenticated %v", m.AuthResults, m.SenderAuthenticated)
	}

	enqueue(t, db, domainID, "auth2")
	m, err = db.GetMessage(ctx, "auth2")
	if err != nil {
		t.Fatal(err)
	}
	if m.AuthResults != "" || m.SenderAuthenticated {
		t.Fatalf("a message enqueued without results reads back %q, authenticated %v", m.AuthResults, m.SenderAuthenticated)
	}
}

func TestADomainWithoutAListAcceptsEveryone(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")

	ok, err := db.RecipientAllowed(ctx, domainID, "anyone@example.com")
	if err != nil || !ok {
		t.Fatalf("RecipientAllowed with no list = %v, %v; want true", ok, err)
	}
}

func TestADomainListIsEnforcedAndNormalised(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	other := newDomain(t, db, "other.com")

	err := db.SetDomainRecipients(ctx, domainID, []string{" Alice@Example.com ", "bob@example.com", "alice@example.com", ""})
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.DomainRecipients(ctx, domainID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"alice@example.com", "bob@example.com"}) {
		t.Fatalf("stored list = %v; want it trimmed, lower-cased and deduplicated", got)
	}

	for addr, want := range map[string]bool{
		"alice@example.com":   true,
		"ALICE@EXAMPLE.COM":   true,
		"carol@example.com":   false,
		"alice@example.com.x": false,
	} {
		ok, err := db.RecipientAllowed(ctx, domainID, addr)
		if err != nil || ok != want {
			t.Fatalf("RecipientAllowed(%q) = %v, %v; want %v", addr, ok, err, want)
		}
	}
	if ok, _ := db.RecipientAllowed(ctx, other, "carol@other.com"); !ok {
		t.Fatal("one domain's list leaked onto another domain")
	}

	if err := db.SetDomainRecipients(ctx, domainID, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.RecipientAllowed(ctx, domainID, "carol@example.com"); !ok {
		t.Fatal("clearing the list did not switch the check off")
	}
}

func TestDeletingADomainDropsItsList(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	if err := db.SetDomainRecipients(ctx, domainID, []string{"alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteDomain(ctx, domainID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domain_recipients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d recipients left behind by a deleted domain", n)
	}
}

func TestBounceBatchClaimsOnlyNullSenderMessages(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	domainID := newDomain(t, db, "example.com")
	now := time.Now().UTC()
	for id, from := range map[string]string{"bounce": "", "submitted": "user@example.com"} {
		err := db.Enqueue(ctx, &Message{
			ID: id, DomainID: domainID, EnvelopeFrom: from,
			EnvelopeTo: []string{"someone@elsewhere.test"}, SizeBytes: 1, ReceivedAt: now,
			ExpiresAt: now.Add(time.Hour), NextRetryAt: now, Direction: DirectionOutbound,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := db.ClaimBounceBatch(ctx, "w", 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "bounce" {
		t.Fatalf("ClaimBounceBatch returned %d messages; want only the bounce", len(got))
	}
	rest, err := db.ClaimOutboundBatch(ctx, "w", 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 1 || rest[0].ID != "submitted" {
		t.Fatalf("ClaimOutboundBatch returned %d messages; want the submitted one", len(rest))
	}
}
