package sender

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/dkim"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const body = "From: postmaster@example.test\r\n" +
	"To: someone@elsewhere.test\r\n" +
	"Subject: a message\r\n" +
	"\r\n" +
	"the body\r\n"

func newSender(t *testing.T) (*Sender, *store.DB, *blob.Store, int64) {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("blob.Open: %v", err)
	}

	id, err := db.CreateDomain(ctx, &store.Domain{
		Name: "example.test", PrimaryHost: "mail.example.test", PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Queue.AllowPrivateDestinations = true
	s := New(cfg.Queue, db, blobs, slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil, nil, nil, cfg.Outbound, "mx2.example.test")
	return s, db, blobs, id
}

func storeKey(t *testing.T, db *store.DB, blobs *blob.Store, domainID int64, enabled bool) {
	t.Helper()
	key, err := dkim.Generate("mail", store.AlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := blobs.Seal(key.PrivatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDKIMKey(context.Background(), &store.DKIMKey{
		DomainID: domainID, Selector: key.Selector, Algorithm: key.Algorithm,
		PrivateKey: sealed, PublicKey: key.PublicB64, Enabled: enabled,
	}); err != nil {
		t.Fatal(err)
	}
}

func signedBody(t *testing.T, s *Sender, m *store.Message) string {
	t.Helper()
	r, err := s.signed(context.Background(), m, strings.NewReader(body))
	if err != nil {
		t.Fatalf("signed: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSignedAddsASignatureWhenTheKeyIsEnabled(t *testing.T) {
	s, db, blobs, id := newSender(t)
	storeKey(t, db, blobs, id, true)

	got := signedBody(t, s, &store.Message{DomainID: id})
	if !strings.Contains(got, "DKIM-Signature:") {
		t.Fatalf("no signature was added:\n%s", got)
	}
	if !strings.Contains(got, "d=example.test") || !strings.Contains(got, "s=mail") {
		t.Errorf("the signature does not name the domain and selector:\n%s", got)
	}
	if !strings.Contains(got, "the body") {
		t.Error("the body did not survive signing")
	}
}

func TestSignedIsAPassthroughWithNoKey(t *testing.T) {
	s, _, _, id := newSender(t)

	if got := signedBody(t, s, &store.Message{DomainID: id}); got != body {
		t.Fatalf("the message was altered with no key configured:\n%s", got)
	}
}

func TestSignedIsAPassthroughWhileTheKeyIsDisabled(t *testing.T) {
	s, db, blobs, id := newSender(t)
	storeKey(t, db, blobs, id, false)

	if got := signedBody(t, s, &store.Message{DomainID: id}); got != body {
		t.Fatalf("a disabled key still signed the message:\n%s", got)
	}
}

func TestSignedFallsBackWhenTheKeyCannotBeRead(t *testing.T) {
	s, db, _, id := newSender(t)

	if err := db.SaveDKIMKey(context.Background(), &store.DKIMKey{
		DomainID: id, Selector: "mail", Algorithm: store.AlgorithmRSA,
		PrivateKey: []byte("this is not sealed ciphertext"),
		PublicKey:  "x", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	if got := signedBody(t, s, &store.Message{DomainID: id}); got != body {
		t.Fatalf("an unreadable key changed the message instead of being skipped:\n%s", got)
	}
}

func TestRouteForPrefersTheMostSpecificMatch(t *testing.T) {
	s, db, _, _ := newSender(t)
	ctx := context.Background()

	for _, r := range []*store.Route{
		{Destination: ".example.com", Mode: "relay", RelayHost: "broad.test",
			RelayPort: 587, RelayTLS: "starttls", Enabled: true},
		{Destination: ".mail.example.com", Mode: "direct", RelayPort: 587,
			RelayTLS: "starttls", Enabled: true},
		{Destination: "exact.com", Mode: "relay", RelayHost: "exact.test",
			RelayPort: 587, RelayTLS: "starttls", Enabled: true},
	} {
		if _, err := db.CreateRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		to      string
		mode    string
		matched string
	}{
		{"user@eu.mail.example.com", "direct", ".mail.example.com"},
		{"user@other.example.com", "relay", ".example.com"},
		{"user@exact.com", "relay", "exact.com"},
		{"user@unrelated.test", s.outbound.Mode, ""},
	}
	for _, tc := range cases {
		mode, route := s.routeFor(ctx, &store.Message{EnvelopeTo: []string{tc.to}})
		if mode != tc.mode {
			t.Errorf("%s: mode = %q, want %q", tc.to, mode, tc.mode)
		}
		switch {
		case tc.matched == "" && route != nil:
			t.Errorf("%s: matched route %q, want the global settings", tc.to, route.Destination)
		case tc.matched != "" && (route == nil || route.Destination != tc.matched):
			t.Errorf("%s: matched %v, want %q", tc.to, route, tc.matched)
		}
	}
}

func TestDisabledRouteIsIgnored(t *testing.T) {
	s, db, _, _ := newSender(t)
	ctx := context.Background()

	if _, err := db.CreateRoute(ctx, &store.Route{
		Destination: "off.test", Mode: "direct", RelayPort: 587,
		RelayTLS: "starttls", Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}

	_, route := s.routeFor(ctx, &store.Message{EnvelopeTo: []string{"user@off.test"}})
	if route != nil {
		t.Fatal("a disabled route was used")
	}
}
