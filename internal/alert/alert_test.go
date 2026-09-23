package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/webhook"
)

type capture struct {
	mu     sync.Mutex
	got    []Alert
	sigs   []string
	stamps []string
	bodies [][]byte
	ch     chan struct{}
}

func newCapture() (*capture, *httptest.Server) {
	c := &capture{ch: make(chan struct{}, 16)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var a Alert
		json.Unmarshal(body, &a)

		c.mu.Lock()
		c.got = append(c.got, a)
		c.sigs = append(c.sigs, r.Header.Get(SignatureHeader))
		c.stamps = append(c.stamps, r.Header.Get(TimestampHeader))
		c.mu.Unlock()

		c.raw(body)
		c.ch <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	return c, srv
}

func (c *capture) raw(body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, append([]byte(nil), body...))
}

func (c *capture) wait(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		c.mu.Lock()
		have := len(c.got)
		c.mu.Unlock()
		if have >= n {
			return
		}
		select {
		case <-c.ch:
		case <-deadline:
			t.Fatalf("only %d alert(s) arrived, want %d", have, n)
		}
	}
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func start(t *testing.T, cfg config.AlertConfig) *Alerter {
	t.Helper()
	cfg.Enabled = true
	a := New(cfg, "mx2.test.example", slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the alerter did not stop when the context was cancelled")
		}
	})
	return a
}

func TestPrimaryDownAlertsAfterTheGracePeriod(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{
		Webhook:          config.WebhookConfig{URL: srv.URL},
		PrimaryDownAfter: 60 * time.Millisecond,
	})

	a.Notify(store.EventPrimaryDown, map[string]any{"domain": "example.test"})
	if c.count() != 0 {
		t.Fatal("an alert was sent before the grace period elapsed")
	}

	c.wait(t, 1)
	c.mu.Lock()
	got := c.got[0]
	c.mu.Unlock()

	if got.Key != "primary_down:example.test" {
		t.Errorf("key = %q", got.Key)
	}
	if got.Severity != SeverityWarning {
		t.Errorf("severity = %q", got.Severity)
	}
	if got.Host != "mx2.test.example" {
		t.Errorf("host = %q", got.Host)
	}
}

func TestShortOutageInsideTheGracePeriodIsSilent(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{
		Webhook:          config.WebhookConfig{URL: srv.URL},
		PrimaryDownAfter: 3 * time.Second,
	})

	a.Notify(store.EventPrimaryDown, map[string]any{"domain": "example.test"})
	time.Sleep(50 * time.Millisecond)
	a.Notify(store.EventPrimaryUp, map[string]any{"domain": "example.test"})

	time.Sleep(300 * time.Millisecond)
	if n := c.count(); n != 0 {
		t.Fatalf("%d alert(s) sent for an outage shorter than the grace period", n)
	}
}

func TestRecoveryIsAnnouncedOnlyAfterAnAlert(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{Webhook: config.WebhookConfig{URL: srv.URL}})

	a.Notify(store.EventPrimaryDown, map[string]any{"domain": "example.test"})
	c.wait(t, 1)

	a.Notify(store.EventPrimaryUp, map[string]any{"domain": "example.test"})
	c.wait(t, 2)

	c.mu.Lock()
	got := c.got[1]
	c.mu.Unlock()
	if got.Key != "primary_up:example.test" || got.Severity != SeverityInfo {
		t.Fatalf("recovery alert = %+v", got)
	}
}

func TestRepeatsAreThrottled(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{
		Webhook:     config.WebhookConfig{URL: srv.URL},
		MinInterval: time.Hour,
	})

	for i := 0; i < 5; i++ {
		a.Notify(store.EventQueueFull, map[string]any{"pending": 1000})
	}
	c.wait(t, 1)
	time.Sleep(200 * time.Millisecond)

	if n := c.count(); n != 1 {
		t.Fatalf("%d alerts sent for the same condition inside min_interval, want 1", n)
	}
}

func TestQueueFullAndExpiryAreCritical(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{Webhook: config.WebhookConfig{URL: srv.URL}})

	a.Notify(store.EventQueueFull, map[string]any{"pending": 1000})
	a.Notify(store.EventMailExpired, map[string]any{"id": "abc"})
	c.wait(t, 2)

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, got := range c.got {
		if got.Severity != SeverityCritical {
			t.Errorf("%s has severity %q, want critical", got.Key, got.Severity)
		}
	}
}

func TestWebhookIsSignedWhenASecretIsSet(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	const secret = "a shared secret"
	a := start(t, config.AlertConfig{
		Webhook: config.WebhookConfig{URL: srv.URL, Secret: secret},
	})

	a.Notify(store.EventQueueFull, map[string]any{"pending": 1000})
	c.wait(t, 1)

	c.mu.Lock()
	sig, body := c.sigs[0], c.bodies[0]
	c.mu.Unlock()

	c.mu.Lock()
	ts := c.stamps[0]
	c.mu.Unlock()
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(n, 0)) > time.Minute {
		t.Fatalf("%s = %q; want the send time", TimestampHeader, ts)
	}
	if want := webhook.Sign([]byte(secret), n, body); sig != want {
		t.Fatalf("signature = %q, want %q: the alert must verify the way event webhooks do", sig, want)
	}
}

func TestNoSignatureWithoutASecret(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{Webhook: config.WebhookConfig{URL: srv.URL}})
	a.Notify(store.EventQueueFull, map[string]any{"pending": 1})
	c.wait(t, 1)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sigs[0] != "" {
		t.Fatalf("a signature was sent with no secret configured: %q", c.sigs[0])
	}
}

func TestUninterestingEventsAreIgnored(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{Webhook: config.WebhookConfig{URL: srv.URL}})
	for _, e := range []string{store.EventMailReceived, store.EventMailDelivered,
		store.EventLogin, store.EventStartup, store.EventMailDeferred} {
		a.Notify(e, map[string]any{"id": "x"})
	}

	time.Sleep(300 * time.Millisecond)
	if n := c.count(); n != 0 {
		t.Fatalf("%d alert(s) raised for routine events", n)
	}
}

func TestNotifyNeverBlocks(t *testing.T) {
	a := New(config.AlertConfig{
		Enabled: true,
		Webhook: config.WebhookConfig{URL: "http://127.0.0.1:1"},
	}, "mx2.test.example", slog.New(slog.NewTextHandler(io.Discard, nil)))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < queueDepth*4; i++ {
			a.Notify(store.EventMailExpired, map[string]any{"id": i})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Notify blocked with a full queue and no consumer")
	}
}

func TestDisabledAlerterDoesNothing(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := New(config.AlertConfig{Enabled: false, Webhook: config.WebhookConfig{URL: srv.URL}},
		"mx2.test.example", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if a.Enabled() {
		t.Fatal("Enabled() is true with enabled: false")
	}
	a.Notify(store.EventQueueFull, map[string]any{"pending": 1})

	time.Sleep(200 * time.Millisecond)
	if n := c.count(); n != 0 {
		t.Fatalf("%d alert(s) sent while disabled", n)
	}
}

func TestEnabledNeedsASink(t *testing.T) {
	a := New(config.AlertConfig{Enabled: true}, "h", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if a.Enabled() {
		t.Fatal("Enabled() is true with no webhook and no recipients")
	}
}

func TestAFailedMessageIsReported(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{Webhook: config.WebhookConfig{URL: srv.URL}})
	a.Notify(store.EventMailFailed, map[string]any{"id": "a", "error": "RCPT TO bob: 550 no such user"})
	a.Notify(store.EventMailFailed, map[string]any{"id": "b", "reason": "body unreadable"})
	c.wait(t, 2)

	c.mu.Lock()
	defer c.mu.Unlock()
	severity := map[string]string{}
	for _, got := range c.got {
		severity[got.Key] = got.Severity
	}
	if severity["mail_failed"] != SeverityWarning {
		t.Errorf("a refusal by the primary has severity %q; want warning", severity["mail_failed"])
	}
	if severity["mail_lost"] != SeverityCritical {
		t.Errorf("a body lost from the spool has severity %q; want critical", severity["mail_lost"])
	}
}

type fakeStatus struct {
	domains []*store.Domain
	status  map[int64]*store.PrimaryStatus
}

func (f fakeStatus) ListDomains(context.Context) ([]*store.Domain, error) { return f.domains, nil }

func (f fakeStatus) PrimaryStatusFor(_ context.Context, id int64) (*store.PrimaryStatus, error) {
	if st, ok := f.status[id]; ok {
		return st, nil
	}
	return nil, store.ErrNotFound
}

func downSince(ago time.Duration) *store.PrimaryStatus {
	now := time.Now().UTC()
	since := now.Add(-ago)
	return &store.PrimaryStatus{IsUp: false, LastCheck: &now, LastDown: &since, LastError: "connection refused"}
}

func TestARestartDuringAnOutageStillAlertsAndAnnouncesTheRecovery(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{
		Webhook:          config.WebhookConfig{URL: srv.URL},
		PrimaryDownAfter: time.Minute,
	})
	up := time.Now().UTC()
	a.Resume(context.Background(), fakeStatus{
		domains: []*store.Domain{
			{ID: 1, Name: "long.test", Enabled: true},
			{ID: 2, Name: "fine.test", Enabled: true},
			{ID: 3, Name: "never.test", Enabled: true},
			{ID: 4, Name: "off.test", Enabled: false},
		},
		status: map[int64]*store.PrimaryStatus{
			1: downSince(5 * time.Minute),
			2: {IsUp: true, LastCheck: &up},
			3: {},
			4: downSince(5 * time.Minute),
		},
	})

	c.wait(t, 1)
	time.Sleep(100 * time.Millisecond)
	if n := c.count(); n != 1 {
		t.Fatalf("%d alerts after the restart; want one, for the primary down past its grace period", n)
	}
	c.mu.Lock()
	got := c.got[0]
	c.mu.Unlock()
	if got.Key != "primary_down:long.test" {
		t.Fatalf("alert key = %q", got.Key)
	}

	a.Notify(store.EventPrimaryUp, map[string]any{"domain": "long.test"})
	c.wait(t, 2)
	c.mu.Lock()
	got = c.got[1]
	c.mu.Unlock()
	if got.Key != "primary_up:long.test" {
		t.Fatalf("recovery alert = %+v; the restart must not lose the recovery notice", got)
	}
}

func TestARestartInsideTheGracePeriodWaitsOnlyForWhatIsLeft(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()

	a := start(t, config.AlertConfig{
		Webhook:          config.WebhookConfig{URL: srv.URL},
		PrimaryDownAfter: 400 * time.Millisecond,
	})
	a.Resume(context.Background(), fakeStatus{
		domains: []*store.Domain{{ID: 1, Name: "recent.test", Enabled: true}},
		status:  map[int64]*store.PrimaryStatus{1: downSince(200 * time.Millisecond)},
	})

	if c.count() != 0 {
		t.Fatal("alerted before the grace period ran out")
	}
	start := time.Now()
	c.wait(t, 1)
	if waited := time.Since(start); waited > 350*time.Millisecond {
		t.Fatalf("alert after %v; want about the 200ms left of the grace period, not a fresh one", waited)
	}
}

func TestADomainAtItsCeilingIsAWarningOfItsOwn(t *testing.T) {
	c, srv := newCapture()
	defer srv.Close()
	a := start(t, config.AlertConfig{Webhook: config.WebhookConfig{URL: srv.URL}, MinInterval: time.Hour})

	for _, d := range []string{"one.test", "two.test", "one.test"} {
		a.Notify(store.EventQueueFull, map[string]any{"reason": "domain_cap", "domain": d})
	}
	a.Notify(store.EventQueueFull, map[string]any{"pending": 100000})

	c.wait(t, 3)
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.got) != 3 {
		t.Fatalf("%d alerts; want one per capped domain (throttled) and one for the whole spool", len(c.got))
	}
	keys := map[string]string{}
	for _, al := range c.got {
		keys[al.Key] = al.Severity
	}
	if keys["queue_full:one.test"] != SeverityWarning || keys["queue_full:two.test"] != SeverityWarning || keys["queue_full"] != SeverityCritical {
		t.Fatalf("alerts = %v", keys)
	}
}
