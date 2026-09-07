package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func newDispatcher(t *testing.T) (*Dispatcher, *store.DB, *blob.Store) {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("blob.Open: %v", err)
	}

	cfg := config.Default().Webhooks
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, db, blobs, "mx2.test", log), db, blobs
}

func TestSignMatchesTheDocumentedConstruction(t *testing.T) {
	body := []byte(`{"event":"mail_received"}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got := Sign([]byte("s3cret"), body); got != want {
		t.Fatalf("Sign = %q, want %q — receivers implement this from the README", got, want)
	}
}

func TestPostSignsWithTheSubscriptionSecret(t *testing.T) {
	d, db, blobs := newDispatcher(t)
	ctx := context.Background()

	var gotSig, gotEvent, gotAttempt string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get(SignatureHeader)
		gotEvent = r.Header.Get(EventHeader)
		gotAttempt = r.Header.Get(AttemptHeader)
	}))
	defer srv.Close()

	sealed, err := blobs.Seal([]byte("the signing secret"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.CreateWebhook(ctx, &store.Webhook{
		Name: "chat", URL: srv.URL, Secret: sealed, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hook, _ := db.Webhook(ctx, id)

	del := &store.Delivery{ID: 7, EventType: store.EventMailReceived, Payload: `{"id":1}`}
	code, err := d.post(ctx, hook, del)
	if err != nil || code != 200 {
		t.Fatalf("post = %d, %v", code, err)
	}

	if want := Sign([]byte("the signing secret"), gotBody); gotSig != want {
		t.Fatalf("SECURITY: the signature does not match the body\n got %q\nwant %q", gotSig, want)
	}
	if gotEvent != store.EventMailReceived {
		t.Errorf("%s = %q", EventHeader, gotEvent)
	}
	if gotAttempt != "1" {
		t.Errorf("%s = %q, want 1", AttemptHeader, gotAttempt)
	}
}

func TestPostLeavesAnUnsignedSubscriptionUnsigned(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(SignatureHeader)]
	}))
	defer srv.Close()

	id, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "plain", URL: srv.URL, Enabled: true})
	hook, _ := db.Webhook(ctx, id)

	if _, err := d.post(ctx, hook, &store.Delivery{EventType: "x", Payload: "{}"}); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("an unsigned subscription received a signature header")
	}
}

func TestPostRefusesWhenTheSecretCannotBeRead(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer srv.Close()

	id, _ := db.CreateWebhook(ctx, &store.Webhook{
		Name: "broken", URL: srv.URL, Enabled: true,
		Secret: []byte("this is not sealed ciphertext"),
	})
	hook, _ := db.Webhook(ctx, id)

	code, err := d.post(ctx, hook, &store.Delivery{EventType: "x", Payload: "{}"})
	if err == nil {
		t.Fatal("SECURITY: an unreadable secret was sent unsigned instead of failing")
	}
	if reached {
		t.Fatal("SECURITY: the payload was delivered without a signature")
	}
	if retryable(code) {
		t.Errorf("a broken secret was treated as retryable (code %d); it will never fix itself", code)
	}
}

func TestRetryable(t *testing.T) {
	cases := map[int]bool{
		0:   true,
		408: true,
		429: true,
		400: false,
		404: false,
		401: false,
		403: false,
		500: true,
		503: true,
	}
	for code, want := range cases {
		if got := retryable(code); got != want {
			t.Errorf("retryable(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestBackoffDoublesUntilTheCap(t *testing.T) {
	d, _, _ := newDispatcher(t)
	d.cfg.RetryBase = time.Second
	d.cfg.RetryMax = 8 * time.Second

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 8 * time.Second},
		{9, 8 * time.Second},
	}
	for _, tc := range cases {
		for i := 0; i < 50; i++ {
			got := d.backoff(tc.attempt)
			if got < tc.want {
				t.Fatalf("backoff(%d) = %v, sooner than the %v it should wait", tc.attempt, got, tc.want)
			}
			if max := tc.want + tc.want/10 + time.Millisecond; got > max {
				t.Fatalf("backoff(%d) = %v, past %v (the delay plus its jitter)", tc.attempt, got, max)
			}
		}
	}
}

func TestBackoffFallsBackOnNonsenseSettings(t *testing.T) {
	d, _, _ := newDispatcher(t)
	d.cfg.RetryBase = 0
	d.cfg.RetryMax = 0

	if got := d.backoff(1); got < 30*time.Second {
		t.Fatalf("backoff with no configuration = %v; it must not become a hot loop", got)
	}
}

func TestAttemptGivesUpAfterMaxAttempts(t *testing.T) {
	d, db, _ := newDispatcher(t)
	d.cfg.MaxAttempts = 3
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "later", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	hookID, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "flaky", URL: srv.URL, Enabled: true})
	delID, _ := db.EnqueueDelivery(ctx, hookID, store.EventStartup, "{}", time.Now().UTC())

	for i := 0; i < 3; i++ {
		rows, err := db.ListDeliveries(ctx, hookID, 1)
		if err != nil || len(rows) == 0 {
			t.Fatal(err)
		}
		d.attempt(ctx, rows[0])
	}

	rows, _ := db.ListDeliveries(ctx, hookID, 1)
	if rows[0].ID != delID {
		t.Fatal("the wrong row came back")
	}
	if rows[0].Status != store.DeliveryFailed {
		t.Fatalf("status = %q after %d attempts, want failed", rows[0].Status, rows[0].Attempts)
	}
	if rows[0].Attempts != 3 {
		t.Errorf("attempts = %d, want 3", rows[0].Attempts)
	}
}

func TestAttemptStopsImmediatelyOnAPermanentRejection(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	hookID, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "gone", URL: srv.URL, Enabled: true})
	db.EnqueueDelivery(ctx, hookID, store.EventStartup, "{}", time.Now().UTC())

	rows, _ := db.ListDeliveries(ctx, hookID, 1)
	d.attempt(ctx, rows[0])

	rows, _ = db.ListDeliveries(ctx, hookID, 1)
	if rows[0].Status != store.DeliveryFailed {
		t.Fatalf("a 404 was scheduled for retry (status %q); it answers the same every time",
			rows[0].Status)
	}
	if calls.Load() != 1 {
		t.Errorf("the endpoint was called %d times for one permanent failure", calls.Load())
	}
}

func TestAttemptFailsWhenTheSubscriptionIsGone(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	hookID, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "x", URL: "https://h.test", Enabled: true})
	del := &store.Delivery{ID: 1, WebhookID: hookID + 999, EventType: "x", Payload: "{}"}
	d.attempt(ctx, del)
}

func TestAttemptRefusesADisabledSubscription(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer srv.Close()

	hookID, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "off", URL: srv.URL, Enabled: false})
	db.EnqueueDelivery(ctx, hookID, store.EventStartup, "{}", time.Now().UTC())

	rows, _ := db.ListDeliveries(ctx, hookID, 1)
	d.attempt(ctx, rows[0])

	if reached.Load() {
		t.Fatal("a disabled subscription still received a delivery")
	}
	rows, _ = db.ListDeliveries(ctx, hookID, 1)
	if rows[0].Status != store.DeliveryFailed {
		t.Fatalf("status = %q, want failed", rows[0].Status)
	}
}

func TestStartCursorBeginsAtTheHead(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		db.RecordEvent(ctx, &store.Event{Type: store.EventStartup})
	}

	cursor, err := d.startCursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 4 {
		t.Fatalf("startCursor = %d on a log of 4, want the head", cursor)
	}

	stored, err := db.MetaInt(ctx, CursorKey)
	if err != nil || stored != 4 {
		t.Fatalf("cursor persisted as %d, %v", stored, err)
	}
}

func TestStartCursorResumes(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		db.RecordEvent(ctx, &store.Event{Type: store.EventStartup})
	}
	if err := db.SetMetaInt(ctx, CursorKey, 2); err != nil {
		t.Fatal(err)
	}

	cursor, err := d.startCursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("startCursor = %d, want the stored position", cursor)
	}
}

func TestDrainFansOutToMatchingSubscriptions(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	wantsAll, _ := db.CreateWebhook(ctx, &store.Webhook{
		Name: "everything", URL: "https://a.test", Enabled: true,
	})
	wantsDown, _ := db.CreateWebhook(ctx, &store.Webhook{
		Name: "outages", URL: "https://b.test", Enabled: true,
		Events: []string{store.EventPrimaryDown},
	})
	disabled, _ := db.CreateWebhook(ctx, &store.Webhook{
		Name: "off", URL: "https://c.test", Enabled: false,
	})

	db.RecordEvent(ctx, &store.Event{Type: store.EventMailReceived})
	db.RecordEvent(ctx, &store.Event{Type: store.EventPrimaryDown})

	cursor, err := d.drain(ctx, 0)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if cursor != 2 {
		t.Fatalf("cursor = %d after draining 2 events", cursor)
	}

	count := func(id int64) int {
		rows, err := db.ListDeliveries(ctx, id, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if got := count(wantsAll); got != 2 {
		t.Errorf("the catch-all subscription got %d deliveries, want 2", got)
	}
	if got := count(wantsDown); got != 1 {
		t.Errorf("the filtered subscription got %d deliveries, want only primary_down", got)
	}
	if got := count(disabled); got != 0 {
		t.Errorf("a disabled subscription got %d deliveries", got)
	}
}

func TestDrainAdvancesWithNoSubscriptions(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	db.RecordEvent(ctx, &store.Event{Type: store.EventStartup})
	db.RecordEvent(ctx, &store.Event{Type: store.EventStartup})

	cursor, err := d.drain(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 2 {
		t.Fatalf("cursor = %d with no subscriptions, want 2", cursor)
	}
	if stored, _ := db.MetaInt(ctx, CursorKey); stored != 2 {
		t.Fatalf("the advanced cursor was not persisted (%d)", stored)
	}
}

func TestPayloadCarriesTheEventID(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	db.CreateWebhook(ctx, &store.Webhook{Name: "x", URL: "https://h.test", Enabled: true})
	queueID := "msg-1"
	db.RecordEvent(ctx, &store.Event{
		Type: store.EventMailReceived, QueueID: &queueID,
		Data: map[string]any{"from": "a@b.test"},
	})

	if _, err := d.drain(ctx, 0); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.ListDeliveries(ctx, 0, 1)
	if len(rows) != 1 {
		t.Fatal("nothing was enqueued")
	}

	var p Payload
	if err := json.Unmarshal([]byte(rows[0].Payload), &p); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}
	if p.ID != 1 {
		t.Errorf("payload id = %d, want the event id", p.ID)
	}
	if p.Event != store.EventMailReceived {
		t.Errorf("payload event = %q", p.Event)
	}
	if p.Node != "mx2.test" {
		t.Errorf("payload node = %q; a fleet needs to know which node spoke", p.Node)
	}
	if p.QueueID == nil || *p.QueueID != "msg-1" {
		t.Error("the payload lost the message id")
	}
}

func TestDeliverDueRunsABatchOnce(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get(DeliveryHeader)]++
		mu.Unlock()
	}))
	defer srv.Close()

	hookID, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "x", URL: srv.URL, Enabled: true})
	for i := 0; i < 5; i++ {
		db.EnqueueDelivery(ctx, hookID, store.EventStartup, "{}", time.Now().UTC())
	}

	d.deliverDue(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 5 {
		t.Fatalf("%d distinct deliveries reached the endpoint, want 5", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("delivery %s arrived %d times; two workers took the same row", id, n)
		}
	}
}

func TestTestSendsASyntheticEvent(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var gotEvent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEvent = r.Header.Get(EventHeader)
	}))
	defer srv.Close()

	id, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "x", URL: srv.URL, Enabled: true})
	hook, _ := db.Webhook(ctx, id)

	code, err := d.Test(ctx, hook)
	if err != nil || code != 200 {
		t.Fatalf("Test = %d, %v", code, err)
	}
	if gotEvent != "test" {
		t.Errorf("%s = %q, want test", EventHeader, gotEvent)
	}

	rows, _ := db.ListDeliveries(ctx, id, 10)
	if len(rows) != 0 {
		t.Errorf("a test button press queued %d deliveries", len(rows))
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	d, db, _ := newDispatcher(t)
	ctx := context.Background()

	var elsewhere atomic.Bool
	final := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		elsewhere.Store(true)
	}))
	defer final.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	id, _ := db.CreateWebhook(ctx, &store.Webhook{Name: "moved", URL: redirector.URL, Enabled: true})
	hook, _ := db.Webhook(ctx, id)

	code, err := d.post(ctx, hook, &store.Delivery{EventType: "x", Payload: "{}"})
	if err == nil {
		t.Fatalf("a redirect was treated as success (code %d)", code)
	}
	if elsewhere.Load() {
		t.Fatal("SECURITY: the payload followed a redirect to another host")
	}
}
