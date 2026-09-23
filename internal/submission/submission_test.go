package submission

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const testPassword = "a submission password that is long"

type harness struct {
	srv   *Server
	addr  string
	db    *store.DB
	blobs *blob.Store
}

func newHarness(t *testing.T, opts ...func(*Server)) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	db, err := store.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("blob.Open: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	cfg := config.Default()
	cfg.Outbound.Enabled = true

	cfg.Outbound.RequireTLS = false
	cfg.Outbound.RelayHost = "smarthost.example"
	cfg.Queue.MinFreeDiskBytes = 0

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg.Outbound, cfg.Queue, db, blobs, log, nil, &metrics.Counters{})
	for _, opt := range opts {
		opt(srv)
	}
	go srv.srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown() })

	return &harness{srv: srv, addr: ln.Addr().String(), db: db, blobs: blobs}
}

func (h *harness) addDomain(t *testing.T, name string) int64 {
	t.Helper()
	id, err := h.db.CreateDomain(context.Background(), &store.Domain{
		Name: name, PrimaryHost: "mail." + name, PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return id
}

func (h *harness) addUser(t *testing.T, username string, allowed []string) {
	t.Helper()
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.CreateSMTPUser(context.Background(), username, hash, allowed); err != nil {
		t.Fatalf("CreateSMTPUser: %v", err)
	}
}

func (h *harness) dial(t *testing.T) *smtp.Client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := smtp.NewClient(conn)
	if err := c.Hello("client.example"); err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func (h *harness) authed(t *testing.T, username string) *smtp.Client {
	t.Helper()
	c := h.dial(t)
	if err := c.Auth(sasl.NewPlainClient("", username, testPassword)); err != nil {
		t.Fatalf("AUTH as %s: %v", username, err)
	}
	return c
}

func TestSubmissionRefusesUnauthenticated(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)

	c := h.dial(t)
	err := c.Mail("someone@example.com", nil)
	if err == nil {
		t.Fatal("SECURITY: accepted MAIL FROM with no authentication: this is an open relay")
	}
}

func TestSubmissionRejectsBadPassword(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)

	c := h.dial(t)
	if err := c.Auth(sasl.NewPlainClient("", "mailserver", "wrong password entirely")); err == nil {
		t.Fatal("SECURITY: authenticated with the wrong password")
	}
}

func TestSubmissionRejectsUnknownAccount(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")

	c := h.dial(t)
	if err := c.Auth(sasl.NewPlainClient("", "nobody", testPassword)); err == nil {
		t.Fatal("SECURITY: authenticated as an account that does not exist")
	}
}

func TestSubmissionAcceptsAndQueuesOutbound(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)

	c := h.authed(t, "mailserver")
	if err := c.Mail("boss@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}

	if err := c.Rcpt("stranger@somewhere-else.example", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: outbound test\r\n\r\nhello world")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("queued %d messages, want 1", len(msgs))
	}
	m := msgs[0]

	if m.Direction != store.DirectionOutbound {
		t.Errorf("direction = %q, want outbound", m.Direction)
	}
	if m.Subject != "outbound test" {
		t.Errorf("subject = %q", m.Subject)
	}
	if len(m.EnvelopeTo) != 1 || m.EnvelopeTo[0] != "stranger@somewhere-else.example" {
		t.Errorf("recipients = %v", m.EnvelopeTo)
	}
}

func TestOutboundIsNotClaimedByInboundWorkers(t *testing.T) {
	h := newHarness(t)
	domainID := h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)
	ctx := context.Background()

	if _, _, err := h.db.RecordProbe(ctx, domainID, true, "", 3, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	c := h.authed(t, "mailserver")
	c.Mail("boss@example.com", nil)
	c.Rcpt("stranger@elsewhere.example", nil)
	w, _ := c.Data()
	io.WriteString(w, "Subject: x\r\n\r\ny")
	w.Close()

	inbound, err := h.db.ClaimBatch(ctx, "worker", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(inbound) != 0 {
		t.Fatalf("SECURITY: the inbound claim picked up %d outbound message(s): "+
			"they would be delivered back to the sender's own primary", len(inbound))
	}

	outbound, err := h.db.ClaimOutboundBatch(ctx, "worker", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(outbound) != 1 {
		t.Fatalf("the outbound claim found %d messages, want 1", len(outbound))
	}
}

func TestAllowedDomainsRestrictTheSender(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "allowed.example")
	h.addDomain(t, "other.example")
	h.addUser(t, "restricted", []string{"allowed.example"})

	c := h.authed(t, "restricted")
	if err := c.Mail("someone@other.example", nil); err == nil {
		t.Fatal("SECURITY: sent as a domain outside the account's allow-list")
	}

	c2 := h.authed(t, "restricted")
	if err := c2.Mail("someone@allowed.example", nil); err != nil {
		t.Fatalf("refused the account's own domain: %v", err)
	}
}

func TestSenderDomainMustBeConfigured(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)

	c := h.authed(t, "mailserver")
	if err := c.Mail("someone@not-configured.example", nil); err == nil {
		t.Fatal("SECURITY: accepted a sender domain that is not configured here")
	}
}

func TestDisabledAccountCannotAuthenticate(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)
	ctx := context.Background()

	user, err := h.db.SMTPUserByName(ctx, "mailserver")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.SetSMTPUserEnabled(ctx, user.ID, false); err != nil {
		t.Fatal(err)
	}

	c := h.dial(t)
	if err := c.Auth(sasl.NewPlainClient("", "mailserver", testPassword)); err == nil {
		t.Fatal("SECURITY: a disabled account authenticated")
	}
}

func TestRequireTLSWithoutCertificateRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Outbound.Enabled = true
	cfg.Outbound.RequireTLS = true
	cfg.Outbound.Addr = "127.0.0.1:0"

	srv := New(cfg.Outbound, cfg.Queue, db, blobs,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, &metrics.Counters{})

	err = srv.ListenAndServe(context.Background())
	if err == nil {
		t.Fatal("started with require_tls and no certificate; nobody could ever authenticate")
	}
	if !contains(err.Error(), "require_tls") {
		t.Errorf("error does not explain the problem: %v", err)
	}
}

func TestMaySend(t *testing.T) {
	cases := []struct {
		name    string
		user    store.SMTPUser
		from    string
		allowed bool
	}{
		{"empty list allows anything", store.SMTPUser{Enabled: true}, "a@any.example", true},
		{"listed domain", store.SMTPUser{Enabled: true, AllowedDomains: []string{"ok.example"}}, "a@ok.example", true},
		{"case insensitive", store.SMTPUser{Enabled: true, AllowedDomains: []string{"ok.example"}}, "a@OK.EXAMPLE", true},
		{"other domain", store.SMTPUser{Enabled: true, AllowedDomains: []string{"ok.example"}}, "a@no.example", false},
		{"disabled account", store.SMTPUser{Enabled: false}, "a@any.example", false},
		{"no at sign", store.SMTPUser{Enabled: true, AllowedDomains: []string{"ok.example"}}, "malformed", false},

		{"null return path", store.SMTPUser{Enabled: true, AllowedDomains: []string{"ok.example"}}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.user.MaySend(tc.from); got != tc.allowed {
				t.Errorf("MaySend(%q) = %v, want %v", tc.from, got, tc.allowed)
			}
		})
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func TestSubmissionAddsATraceHeaderAndAnnouncesItsName(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.SetHostname("mx2.example.com") })
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)

	c := h.authed(t, "mailserver")
	if err := c.Mail("boss@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("stranger@somewhere-else.example", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	body := "Subject: traced\r\n\r\nhello\r\n"
	io.WriteString(w, body)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("ListMessages = %d, %v", len(msgs), err)
	}
	rc, err := h.blobs.Get(msgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)

	want := "Received: from client.example ([127.0.0.1])\r\n" +
		"\tby mx2.example.com (XeronMX) with ESMTPA id " + msgs[0].ID + "\r\n" +
		"\tfor <stranger@somewhere-else.example>; "
	if !strings.HasPrefix(string(got), want) || !strings.HasSuffix(string(got), "\r\n"+body) {
		t.Fatalf("spooled message =\n%q\nwant it to start with\n%q\nand end with the submitted message", got, want)
	}
}

func TestSubmissionRefusesALoop(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)

	c := h.authed(t, "mailserver")
	if err := c.Mail("boss@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("stranger@somewhere-else.example", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, strings.Repeat("Received: from a by b; Wed, 23 Sep 2026 14:57:57 +0000\r\n", 50)+"Subject: loop\r\n\r\nx")
	err = w.Close()
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 554 {
		t.Fatalf("DATA with 50 hops = %v; want 554", err)
	}
	if msgs, _ := h.db.ListMessages(context.Background(), store.ListFilter{}); len(msgs) != 0 {
		t.Fatalf("queued %d messages, want none", len(msgs))
	}
}
