package spam

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

func newChecker(t *testing.T, url string, tweak func(*config.SpamConfig)) *Checker {
	t.Helper()
	cfg := config.Default().Spam
	cfg.Enabled = true
	cfg.URL = url
	cfg.Timeout = 2 * time.Second
	if tweak != nil {
		tweak(&cfg)
	}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func check(t *testing.T, c *Checker, body string) Verdict {
	t.Helper()
	return c.Check(context.Background(), Envelope{
		From: "sender@example.net", To: []string{"user@example.com"},
		HeloName: "mail.example.net", RemoteAddr: "198.51.100.7:53422",
		QueueID: "abc123",
	}, strings.NewReader(body), int64(len(body)))
}

func TestUnreachableRspamdAcceptsTheMessage(t *testing.T) {

	c := newChecker(t, "http://127.0.0.1:1", nil)

	v := check(t, c, "Subject: hello\r\n\r\nbody")
	if v.Reject() || v.Defer() {
		t.Fatalf("SECURITY: an unreachable filter blocked the message: %+v", v)
	}
	if !v.Skipped {
		t.Error("verdict should be marked skipped so the log says why")
	}
}

func TestSlowRspamdAcceptsTheMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Write([]byte(`{"action":"reject","score":99}`))
	}))
	defer srv.Close()

	c := newChecker(t, srv.URL, func(cfg *config.SpamConfig) {
		cfg.Timeout = 150 * time.Millisecond
	})
	v := check(t, c, "body")
	if v.Reject() {
		t.Fatal("a filter that timed out rejected the message")
	}
	if !v.Skipped {
		t.Error("timeout should produce a skipped verdict")
	}
}

func TestGarbageResponseAcceptsTheMessage(t *testing.T) {
	for _, body := range []string{"not json at all", "", "{{{"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}))
		c := newChecker(t, srv.URL, nil)
		if v := check(t, c, "body"); v.Reject() || v.Defer() {
			t.Errorf("unparseable response %q blocked the message", body)
		}
		srv.Close()
	}
}

func TestServerErrorAcceptsTheMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "scanner exploded", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if v := check(t, newChecker(t, srv.URL, nil), "body"); v.Reject() {
		t.Fatal("a 500 from rspamd rejected the message")
	}
}

func TestVerdictParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"action":"add header","score":7.5,"required_score":15,
			"symbols":{"BAYES_SPAM":{"score":3.5},"NEUTRAL":{"score":0}}
		}`)
	}))
	defer srv.Close()

	v := check(t, newChecker(t, srv.URL, nil), "body")
	if v.Action != ActionAddHeader {
		t.Errorf("action = %q, want %q", v.Action, ActionAddHeader)
	}
	if v.Score != 7.5 || v.Required != 15 {
		t.Errorf("score = %v, required = %v", v.Score, v.Required)
	}
	if !v.Spammy() || v.Reject() || v.Defer() {
		t.Error("add header should tag the message without blocking it")
	}

	if len(v.Symbols) != 1 || v.Symbols[0] != "BAYES_SPAM" {
		t.Errorf("symbols = %v, want only the ones that scored", v.Symbols)
	}
}

func TestRejectIsDowngradedUnlessEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"action":"reject","score":42,"required_score":15}`)
	}))
	defer srv.Close()

	off := check(t, newChecker(t, srv.URL, nil), "body")
	if off.Reject() {
		t.Error("rejected with reject_enabled off")
	}
	if !off.Spammy() {
		t.Error("a downgraded reject should still tag the message")
	}

	on := check(t, newChecker(t, srv.URL, func(c *config.SpamConfig) {
		c.RejectEnabled = true
	}), "body")
	if !on.Reject() {
		t.Error("did not reject with reject_enabled on")
	}
}

func TestGreylistIsADefer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"action":"greylist","score":5}`)
	}))
	defer srv.Close()

	v := check(t, newChecker(t, srv.URL, nil), "body")
	if !v.Defer() || v.Reject() {
		t.Fatalf("greylist should defer, not reject: %+v", v)
	}
}

func TestEnvelopeIsForwardedToRspamd(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, `{"action":"no action","score":0}`)
	}))
	defer srv.Close()

	check(t, newChecker(t, srv.URL, nil), "body")
	h := <-seen

	if got := h.Get("From"); got != "sender@example.net" {
		t.Errorf("From header = %q", got)
	}
	if got := h.Get("Rcpt"); got != "user@example.com" {
		t.Errorf("Rcpt header = %q", got)
	}
	if got := h.Get("Helo"); got != "mail.example.net" {
		t.Errorf("Helo header = %q", got)
	}

	if got := h.Get("IP"); got != "198.51.100.7" {
		t.Errorf("IP header = %q, want the address without the port", got)
	}
	if got := h.Get("Queue-Id"); got != "abc123" {
		t.Errorf("Queue-Id header = %q", got)
	}
}

func TestLargeMessagesSkipTheScan(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		io.WriteString(w, `{"action":"reject"}`)
	}))
	defer srv.Close()

	c := newChecker(t, srv.URL, func(cfg *config.SpamConfig) { cfg.MaxSizeBytes = 100 })
	v := c.Check(context.Background(), Envelope{From: "a@b.example"},
		strings.NewReader("x"), 5000)

	if called {
		t.Error("a message over the size limit was still sent to the scanner")
	}
	if v.Reject() || !v.Skipped {
		t.Errorf("oversized message should be accepted unscanned: %+v", v)
	}
}

func TestDisabledCheckerNeverCalls(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := newChecker(t, srv.URL, func(cfg *config.SpamConfig) { cfg.Enabled = false })
	if c.Enabled() {
		t.Fatal("checker reports enabled with enabled:false")
	}
	if v := check(t, c, "body"); !v.Skipped || v.Reject() {
		t.Errorf("disabled checker produced %+v", v)
	}
	if called {
		t.Error("disabled checker still called rspamd")
	}
}

func TestHeaders(t *testing.T) {
	score := 7.25

	if got := Headers("no action", &score); got != "" {
		t.Errorf("a clean message got headers: %q", got)
	}
	if got := Headers("", nil); got != "" {
		t.Errorf("an unscanned message got headers: %q", got)
	}

	got := Headers("add header", &score)
	for _, want := range []string{
		"X-Spam-Checked-By: XeronMX\r\n",
		"X-Spam-Action: add header\r\n",
		"X-Spam-Score: 7.25\r\n",
		"X-Spam-Flag: YES\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("headers missing %q, got:\n%s", want, got)
		}
	}

	if !strings.HasSuffix(got, "\r\n") {
		t.Error("header block does not end with CRLF")
	}
}

func TestHeaderInjectionIsStripped(t *testing.T) {
	got := Headers("evil\r\nX-Injected: yes\r\nSubject: hijacked", nil)

	lines := strings.Split(strings.TrimSuffix(got, "\r\n"), "\r\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "X-Spam-") {
			t.Fatalf("SECURITY: injected header line %q in:\n%s", line, got)
		}
	}
	if len(lines) != 2 {
		t.Errorf("expected exactly two header lines, got %d:\n%s", len(lines), got)
	}

	if strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\n") {
		t.Error("a stray newline survived sanitisation")
	}
}

func TestPassthroughRejectIsHonoured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"is_skipped": true,
			"score": 15.0,
			"required_score": 15.0,
			"action": "reject",
			"passthrough_module": "GTUBE",
			"messages": {"smtp_message": "Gtube pattern"},
			"symbols": {"GTUBE": {"name": "GTUBE", "score": 0.0}}
		}`)
	}))
	defer srv.Close()

	c := newChecker(t, srv.URL, func(cfg *config.SpamConfig) { cfg.RejectEnabled = true })

	v := check(t, c, "Subject: spam\r\n\r\nGTUBE")
	if !v.Reject() {
		t.Fatalf("SECURITY: rspamd said reject and the message was accepted: %+v", v)
	}
	if v.Skipped {
		t.Error("the verdict is marked skipped, so the score would not be recorded")
	}
	if v.Score != 15 {
		t.Errorf("score = %v, want the one rspamd reported", v.Score)
	}
}

func TestGenuinelySkippedMessageIsAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"is_skipped": true, "score": 0, "required_score": 15,
			"action": "no action", "symbols": {}}`)
	}))
	defer srv.Close()

	c := newChecker(t, srv.URL, nil)

	v := check(t, c, "Subject: hello\r\n\r\nbody")
	if v.Reject() || v.Defer() {
		t.Fatalf("a message rspamd declined to scan was blocked: %+v", v)
	}
	if !v.Skipped {
		t.Error("the verdict does not report that no scan happened")
	}
}

func TestPassthroughSoftRejectDefers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"is_skipped": true, "score": 0, "required_score": 15,
			"action": "soft reject", "passthrough_module": "RATELIMIT", "symbols": {}}`)
	}))
	defer srv.Close()

	c := newChecker(t, srv.URL, nil)

	v := check(t, c, "Subject: hello\r\n\r\nbody")
	if !v.Defer() {
		t.Fatalf("a rate-limited message was accepted outright: %+v", v)
	}
}
