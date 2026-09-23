package smtpd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/pires/go-proxyproto"

	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/clamav"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/filter"
	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/proxy"
	"github.com/xeron-be/xeron-mx/internal/spam"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type harness struct {
	srv     *Server
	filters *filter.Set
	addr    string
	db      *store.DB
	blobs   *blob.Store
}

func newHarness(t *testing.T) *harness {
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
	cfg.SMTP.Hostname = "mx-test.example"
	cfg.SMTP.MaxMessageBytes = 1 << 20
	cfg.Queue.MinFreeDiskBytes = 0

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	filters := filter.New(db, log)
	if err := filters.Load(context.Background()); err != nil {
		t.Fatalf("filters.Load: %v", err)
	}
	srv, err := New(cfg.SMTP, cfg.Queue, db, blobs, log, nil, &metrics.Counters{},
		spam.New(cfg.Spam, log), filters)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go srv.srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown() })

	return &harness{srv: srv, addr: ln.Addr().String(), db: db, blobs: blobs, filters: filters}
}

func (h *harness) addDomain(t *testing.T, name string, enabled bool) int64 {
	t.Helper()
	id, err := h.db.CreateDomain(context.Background(), &store.Domain{
		Name: name, PrimaryHost: "mail." + name, PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: enabled,
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return id
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

func (h *harness) send(t *testing.T, from, to, body string) error {
	t.Helper()
	c := h.dial(t)
	if err := c.Mail(from, nil); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to, nil); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	return w.Close()
}

func TestRefusesRelayForUnknownDomain(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "known.example", true)

	err := h.send(t, "spammer@evil.example", "victim@somewhere-else.example",
		"Subject: spam\r\n\r\nbuy things\r\n")
	if err == nil {
		t.Fatal("SECURITY: accepted mail for an unconfigured domain: this is an open relay")
	}

	var smtpErr *smtp.SMTPError
	if !asSMTPError(err, &smtpErr) {
		t.Fatalf("expected an SMTP error, got %v", err)
	}
	if smtpErr.Code != 550 {
		t.Fatalf("rejected with %d, want 550", smtpErr.Code)
	}

	if !strings.Contains(strings.ToLower(smtpErr.Message), "relay") {
		t.Errorf("rejection message %q does not mention relaying", smtpErr.Message)
	}
}

func TestRefusesRelayForDisabledDomain(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "paused.example", false)

	if err := h.send(t, "a@b.example", "user@paused.example", "Subject: x\r\n\r\nbody\r\n"); err == nil {
		t.Fatal("accepted mail for a disabled domain")
	}
}

func TestAcceptsAndSpoolsMailForConfiguredDomain(t *testing.T) {
	h := newHarness(t)
	domainID := h.addDomain(t, "known.example", true)

	body := "Subject: quarterly report\r\nFrom: a@b.example\r\n\r\nthe body\r\n"
	if err := h.send(t, "a@b.example", "user@known.example", body); err != nil {
		t.Fatalf("legitimate mail was refused: %v", err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("spooled %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Status != store.StatusQueued {
		t.Errorf("status = %s, want queued", m.Status)
	}
	if m.EnvelopeFrom != "a@b.example" {
		t.Errorf("envelope from = %q", m.EnvelopeFrom)
	}
	if len(m.EnvelopeTo) != 1 || m.EnvelopeTo[0] != "user@known.example" {
		t.Errorf("envelope to = %v", m.EnvelopeTo)
	}
	if m.Subject != "quarterly report" {
		t.Errorf("subject = %q, want %q", m.Subject, "quarterly report")
	}

	rc, err := h.blobs.Get(m.ID)
	if err != nil {
		t.Fatalf("body not in spool: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	trace := "Received: from client.example ([127.0.0.1])\r\n" +
		"\tby mx-test.example (XeronMX) with ESMTP id " + m.ID + "\r\n" +
		"\tfor <user@known.example>; "
	if !strings.HasPrefix(string(got), trace) {
		t.Errorf("spooled body does not start with the trace header:\ngot  %q\nwant %q...", got, trace)
	}
	if !strings.HasSuffix(string(got), "\r\n"+body) {
		t.Errorf("spooled body differs from what was sent after the trace header:\ngot  %q\nwant ...%q", got, body)
	}
	if m.SizeBytes != int64(len(got)) {
		t.Errorf("size = %d, want %d including the trace header", m.SizeBytes, len(got))
	}
}

func TestRefusesAMessageThatLoopedTooManyTimes(t *testing.T) {
	h := newHarness(t)
	domainID := h.addDomain(t, "known.example", true)

	var hops strings.Builder
	for i := 0; i < 49; i++ {
		hops.WriteString("Received: from a by b; Wed, 23 Sep 2026 14:57:57 +0000\r\n")
	}
	if err := h.send(t, "a@b.example", "user@known.example", hops.String()+"Subject: 49\r\n\r\nok\r\n"); err != nil {
		t.Fatalf("49 hops were refused: %v", err)
	}

	hops.WriteString("Received: from a by b; Wed, 23 Sep 2026 14:57:57 +0000\r\n")
	err := h.send(t, "a@b.example", "user@known.example", hops.String()+"Subject: 50\r\n\r\nloop\r\n")
	var se *smtp.SMTPError
	if !asSMTPError(err, &se) || se.Code != 554 || se.EnhancedCode != (smtp.EnhancedCode{5, 4, 6}) {
		t.Fatalf("50 hops: err = %v; want 554 5.4.6", err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("spooled %d messages, want only the 49-hop one", len(msgs))
	}
}

func TestAcceptsNullReturnPath(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "known.example", true)

	if err := h.send(t, "", "user@known.example", "Subject: bounce\r\n\r\nundeliverable\r\n"); err != nil {
		t.Fatalf("null return path was refused: %v", err)
	}
}

func TestRejectsMalformedRecipient(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "known.example", true)

	c := h.dial(t)
	if err := c.Mail("a@b.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("no-at-sign", nil); err == nil {
		t.Fatal("accepted a recipient with no domain part")
	}
}

func TestRejectsSecondRecipientDomain(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "one.example", true)
	h.addDomain(t, "two.example", true)

	c := h.dial(t)
	if err := c.Mail("a@b.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("user@one.example", nil); err != nil {
		t.Fatalf("first recipient refused: %v", err)
	}
	err := c.Rcpt("user@two.example", nil)
	if err == nil {
		t.Fatal("accepted recipients in two different domains in one transaction")
	}

	var smtpErr *smtp.SMTPError
	if asSMTPError(err, &smtpErr) && smtpErr.Code >= 500 {
		t.Errorf("rejected permanently with %d, want a 4xx so the sender retries", smtpErr.Code)
	}
}

func TestAcceptsMultipleRecipientsInSameDomain(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "known.example", true)

	c := h.dial(t)
	if err := c.Mail("a@b.example", nil); err != nil {
		t.Fatal(err)
	}
	for _, rcpt := range []string{"one@known.example", "two@known.example", "three@known.example"} {
		if err := c.Rcpt(rcpt, nil); err != nil {
			t.Fatalf("recipient %s refused: %v", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: team\r\n\r\nhello\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("spooled %d messages, want 1 carrying all recipients", len(msgs))
	}
	if len(msgs[0].EnvelopeTo) != 3 {
		t.Fatalf("kept %d recipients, want 3", len(msgs[0].EnvelopeTo))
	}
}

func TestRecipientDomainIsCaseInsensitive(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "known.example", true)

	if err := h.send(t, "a@b.example", "User@KNOWN.EXAMPLE", "Subject: x\r\n\r\ny\r\n"); err != nil {
		t.Fatalf("uppercase recipient domain was refused: %v", err)
	}
}

func TestSubjectExtraction(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
	}{
		{"simple", "Subject: hello\r\n\r\nbody", "hello"},
		{"lowercase header", "subject: hello\r\n\r\nbody", "hello"},
		{"after other headers", "From: a@b.c\r\nSubject: hello\r\nTo: d@e.f\r\n\r\nbody", "hello"},
		{"folded across lines", "Subject: a very\r\n long subject\r\n\r\nbody", "a very long subject"},
		{"absent", "From: a@b.c\r\n\r\nSubject: not a header\r\n", ""},
		{"empty value", "Subject:\r\n\r\nbody", ""},
		{"bare newlines", "Subject: unix style\n\nbody", "unix style"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractSubject([]byte(tc.head)); got != tc.want {
				t.Errorf("extractSubject() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMessageIDsAreUniqueAndOpaque(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 {
			t.Fatalf("id %q is %d chars, want 32", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate id generated: %s", id)
		}
		seen[id] = true
	}
}

func asSMTPError(err error, target **smtp.SMTPError) bool {
	for err != nil {
		if e, ok := err.(*smtp.SMTPError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (h *harness) addFilter(t *testing.T, name, field, pattern, action string) {
	t.Helper()
	if _, err := h.db.CreateFilter(context.Background(), &store.Filter{
		Name: name, Field: field, Pattern: pattern,
		Action: action, Enabled: true, Priority: 10,
	}); err != nil {
		t.Fatalf("CreateFilter: %v", err)
	}
	if err := h.filters.Load(context.Background()); err != nil {
		t.Fatalf("filters.Load: %v", err)
	}
}

func TestFilterRejectsAtSMTPTime(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)
	h.addFilter(t, "no invoices", store.FieldSubject, "invoice", store.FilterReject)

	err := h.send(t, "sender@outside.test", "user@example.test",
		"Subject: Your invoice\r\n\r\nbody\r\n")
	if err == nil {
		t.Fatal("a message matching a reject filter was accepted")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Fatalf("rejection was %v, want a 550", err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("%d message(s) queued after a reject", len(msgs))
	}
}

func TestFilterQuarantineAcceptsButHolds(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)
	h.addFilter(t, "suspicious", store.FieldSubject, "lottery", store.FilterQuarantine)

	if err := h.send(t, "sender@outside.test", "user@example.test",
		"Subject: You won the lottery\r\n\r\nbody\r\n"); err != nil {
		t.Fatalf("a quarantined message was refused instead of accepted: %v", err)
	}

	ctx := context.Background()
	n, err := h.db.CountQuarantined(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d messages quarantined, want 1", n)
	}

	claimed, err := h.db.ClaimBatch(ctx, "worker", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 0 {
		t.Fatal("SECURITY: a quarantined message was claimed for delivery")
	}
}

func TestReleasedMessageBecomesDeliverable(t *testing.T) {
	h := newHarness(t)
	id := h.addDomain(t, "example.test", true)
	h.addFilter(t, "hold", store.FieldSubject, "hold me", store.FilterQuarantine)

	if err := h.send(t, "sender@outside.test", "user@example.test",
		"Subject: hold me\r\n\r\nbody\r\n"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := h.db.RecordProbe(ctx, id, true, "", 3, 1, time.Now().UTC()); err != nil {
		t.Fatalf("RecordProbe: %v", err)
	}

	msgs, err := h.db.ListMessages(ctx, store.ListFilter{})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("expected one queued message, got %d (%v)", len(msgs), err)
	}
	if err := h.db.Release(ctx, msgs[0].ID, time.Now().UTC()); err != nil {
		t.Fatalf("Release: %v", err)
	}

	claimed, err := h.db.ClaimBatch(ctx, "worker", 10, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 {
		t.Fatalf("%d messages claimable after release, want 1", len(claimed))
	}
}

func TestMailWithNoMatchingFilterIsUntouched(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)
	h.addFilter(t, "no invoices", store.FieldSubject, "invoice", store.FilterReject)

	if err := h.send(t, "sender@outside.test", "user@example.test",
		"Subject: ordinary mail\r\n\r\nbody\r\n"); err != nil {
		t.Fatalf("ordinary mail was refused: %v", err)
	}
	n, err := h.db.CountQuarantined(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("ordinary mail was quarantined")
	}
}

func startMockClamAVServer(t *testing.T, resp string) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						break
					}
					if bytes.Contains(buf[:n], []byte("\x00\x00\x00\x00")) {
						_, _ = c.Write([]byte(resp))
						break
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		ln.Close()
	}
}

func TestClamAVRejectMalware(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)

	addr, cleanup := startMockClamAVServer(t, "stream: Win.Test.EICAR_HDB-1 FOUND\x00")
	defer cleanup()

	scanner := clamav.New(config.ClamAVConfig{
		Enabled: true,
		Addr:    addr,
		Timeout: 2 * time.Second,
		Action:  "reject",
	})
	h.srv.SetClamAV(scanner)

	err := h.send(t, "attacker@outside.test", "user@example.test",
		"Subject: infected\r\n\r\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n")
	if err == nil {
		t.Fatalf("expected mail to be rejected by ClamAV")
	}
	if !strings.Contains(err.Error(), "Malware detected") {
		t.Fatalf("expected Malware detected error, got: %v", err)
	}
}

func TestClamAVQuarantineMalware(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)

	addr, cleanup := startMockClamAVServer(t, "stream: Win.Test.EICAR_HDB-1 FOUND\x00")
	defer cleanup()

	scanner := clamav.New(config.ClamAVConfig{
		Enabled: true,
		Addr:    addr,
		Timeout: 2 * time.Second,
		Action:  "quarantine",
	})
	h.srv.SetClamAV(scanner)

	err := h.send(t, "attacker@outside.test", "user@example.test",
		"Subject: infected\r\n\r\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n")
	if err != nil {
		t.Fatalf("expected quarantined mail to be accepted at SMTP time, got: %v", err)
	}

	n, err := h.db.CountQuarantined(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 quarantined message, got %d", n)
	}
}

func TestDrainModeReturns421(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)

	m := maintenance.NewManager(true)
	h.srv.SetMaintenance(m)

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	c := smtp.NewClient(conn)
	err = c.Hello("client.example")
	if err == nil {
		t.Fatal("expected error in drain mode, got nil")
	}
	if !strings.Contains(err.Error(), "421") {
		t.Fatalf("expected 421 response, got: %v", err)
	}

	m.SetDraining(false)
	err = h.send(t, "sender@outside.test", "user@example.test", "Subject: test\r\n\r\nbody\r\n")
	if err != nil {
		t.Fatalf("expected success after disabling drain mode, got: %v", err)
	}
}

func TestDiskGuardReturns452(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.test", true)

	h.srv.SetDiskGuard("/spool", 1000, func(path string) (uint64, error) {
		return 500, nil
	})

	err := h.send(t, "sender@outside.test", "user@example.test", "Subject: test\r\n\r\nbody\r\n")
	if err == nil {
		t.Fatal("expected 452 error when disk is below threshold, got nil")
	}
	if !strings.Contains(err.Error(), "452") {
		t.Fatalf("expected 452 response, got: %v", err)
	}

	h.srv.SetDiskGuard("/spool", 1000, func(path string) (uint64, error) {
		return 2000, nil
	})

	err = h.send(t, "sender@outside.test", "user@example.test", "Subject: test\r\n\r\nbody\r\n")
	if err != nil {
		t.Fatalf("expected success when disk is above threshold, got: %v", err)
	}
}

type notified struct {
	mu     sync.Mutex
	events []map[string]any
}

func (n *notified) Notify(event string, payload map[string]any) {
	if event != store.EventQueueFull {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, payload)
}

func TestADomainAtItsCeilingIsRefusedAndReported(t *testing.T) {
	h := newHarness(t)
	n := &notified{}
	h.srv.notify = n
	ceiling := int64(1)
	id, err := h.db.CreateDomain(context.Background(), &store.Domain{
		Name: "capped.example", PrimaryHost: "mail.capped.example", PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true, MaxQueueMessages: &ceiling,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.addDomain(t, "open.example", true)

	if err := h.send(t, "a@b.example", "user@capped.example", "Subject: 1\r\n\r\nx\r\n"); err != nil {
		t.Fatalf("first message refused: %v", err)
	}
	err = h.send(t, "a@b.example", "user@capped.example", "Subject: 2\r\n\r\nx\r\n")
	var se *smtp.SMTPError
	if !asSMTPError(err, &se) || se.Code != 452 {
		t.Fatalf("second message: %v; want 452 at the domain's ceiling", err)
	}
	if err := h.send(t, "a@b.example", "user@open.example", "Subject: 3\r\n\r\nx\r\n"); err != nil {
		t.Fatalf("another domain was refused: %v", err)
	}

	n.mu.Lock()
	got := n.events
	n.mu.Unlock()
	if len(got) != 1 || got[0]["reason"] != "domain_cap" || got[0]["domain"] != "capped.example" {
		t.Fatalf("notifications = %v; want one domain_cap for capped.example", got)
	}
	events, err := h.db.ListEventsForDomains(context.Background(), []int64{id}, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		found = found || e.Type == store.EventQueueFull
	}
	if !found {
		t.Fatal("the refusal is not on the domain's timeline")
	}
}

func TestTheMalwareScanOutcomeIsRecordedOnTheMessage(t *testing.T) {
	clean, stopClean := startMockClamAVServer(t, "stream: OK\x00")
	defer stopClean()
	infected, stopInfected := startMockClamAVServer(t, "stream: Win.Test.EICAR_HDB-1 FOUND\x00")
	defer stopInfected()
	down, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := down.Addr().String()
	down.Close()

	big := "Subject: big\r\n\r\n" + strings.Repeat(strings.Repeat("x", 70)+"\r\n", 60)
	cases := []struct {
		name, addr, body, want string
		maxSize                int64
	}{
		{"clean", clean, "Subject: fine\r\n\r\nhello\r\n", "clean", 0},
		{"infected and quarantined", infected, "Subject: bad\r\n\r\nx\r\n", "infected: Win.Test.EICAR_HDB-1", 0},
		{"too large to scan", unreachable, big, "skipped: larger than 1024 bytes", 1024},
		{"clamd unreachable", unreachable, "Subject: fine\r\n\r\nhello\r\n", "failed: ", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			domainID := h.addDomain(t, "example.test", true)
			h.srv.SetClamAV(clamav.New(config.ClamAVConfig{
				Enabled: true, Addr: c.addr, Timeout: time.Second, Action: "quarantine", MaxSizeBytes: c.maxSize,
			}))

			if err := h.send(t, "a@outside.test", "user@example.test", c.body); err != nil {
				t.Fatalf("the message was refused: %v; a scan outcome must never cost the mail", err)
			}
			msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
			if err != nil || len(msgs) != 1 {
				t.Fatalf("ListMessages = %d, %v", len(msgs), err)
			}
			if !strings.HasPrefix(msgs[0].MalwareScan, c.want) {
				t.Fatalf("malware_scan = %q; want %q...", msgs[0].MalwareScan, c.want)
			}
		})
	}
}

func TestMailThroughATrustedBalancerKeepsTheClientAddress(t *testing.T) {
	h := newHarness(t)
	domainID := h.addDomain(t, "known.example", true)

	trusted, err := proxy.ParseTrusted([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go h.srv.srv.Serve(proxy.Listen(ln, trusted))

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	hdr := &proxyproto.Header{
		Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.TCPv4,
		SourceAddr:      &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40123},
		DestinationAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 25},
	}
	if _, err := hdr.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	c := smtp.NewClient(conn)
	defer c.Close()
	if err := c.Hello("client.example"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("a@b.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("user@known.example", nil); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: via the balancer\r\n\r\nhello\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("ListMessages = %d, %v", len(msgs), err)
	}
	if msgs[0].RemoteAddr != "203.0.113.7:40123" {
		t.Fatalf("remote address = %q; want the client's, not the balancer's", msgs[0].RemoteAddr)
	}
	rc, err := h.blobs.Get(msgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if !strings.HasPrefix(string(body), "Received: from client.example ([203.0.113.7])") {
		t.Fatalf("trace header = %q", string(body)[:80])
	}
}
