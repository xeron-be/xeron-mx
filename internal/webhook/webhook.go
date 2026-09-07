package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const CursorKey = "webhook.cursor"

const (
	tailInterval  = 2 * time.Second
	workInterval  = 5 * time.Second
	tailBatch     = 200
	deliverBatch  = 50
	purgeInterval = 6 * time.Hour
)

type Unsealer interface {
	Unseal(sealed []byte) ([]byte, error)
}

type Dispatcher struct {
	cfg    config.WebhooksConfig
	db     *store.DB
	seal   Unsealer
	log    *slog.Logger
	node   string
	client *http.Client
}

func New(cfg config.WebhooksConfig, db *store.DB, seal Unsealer, node string, log *slog.Logger) *Dispatcher {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Dispatcher{
		cfg:  cfg,
		db:   db,
		seal: seal,
		log:  log,
		node: node,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (d *Dispatcher) Enabled() bool { return d.cfg.Enabled }

func (d *Dispatcher) Run(ctx context.Context) {
	if !d.Enabled() {
		return
	}
	d.log.Info("event webhooks enabled",
		"workers", d.cfg.Workers, "max_attempts", d.cfg.MaxAttempts)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); d.tail(ctx) }()
	go func() { defer wg.Done(); d.deliverLoop(ctx) }()
	go func() { defer wg.Done(); d.purgeLoop(ctx) }()
	wg.Wait()
}

func (d *Dispatcher) tail(ctx context.Context) {
	cursor, err := d.startCursor(ctx)
	if err != nil {
		d.log.Error("webhooks: could not establish a starting point, not tailing", "error", err)
		return
	}
	d.log.Debug("webhook tailer started", "cursor", cursor)

	ticker := time.NewTicker(tailInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if next, err := d.drain(ctx, cursor); err != nil {
				if ctx.Err() == nil {
					d.log.Error("webhooks: reading the event log failed", "error", err)
				}
			} else {
				cursor = next
			}
		}
	}
}

func (d *Dispatcher) startCursor(ctx context.Context) (int64, error) {
	cursor, err := d.db.MetaInt(ctx, CursorKey)
	if err == nil {
		return cursor, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	head, err := d.db.MaxEventID(ctx)
	if err != nil {
		return 0, err
	}
	if err := d.db.SetMetaInt(ctx, CursorKey, head); err != nil {
		return 0, err
	}
	return head, nil
}

func (d *Dispatcher) drain(ctx context.Context, cursor int64) (int64, error) {
	events, err := d.db.EventsSince(ctx, cursor, tailBatch)
	if err != nil {
		return cursor, err
	}
	if len(events) == 0 {
		return cursor, nil
	}

	hooks, err := d.db.ListWebhooks(ctx)
	if err != nil {
		return cursor, err
	}

	for _, e := range events {
		for _, h := range hooks {
			if !h.Wants(e.Type) {
				continue
			}
			payload, err := render(e, d.node)
			if err != nil {
				d.log.Error("webhooks: could not render an event", "event", e.Type, "error", err)
				continue
			}
			if _, err := d.db.EnqueueDelivery(ctx, h.ID, e.Type, payload, time.Now().UTC()); err != nil {
				return cursor, fmt.Errorf("enqueue for webhook %d: %w", h.ID, err)
			}
		}
		cursor = e.ID
	}

	if err := d.db.SetMetaInt(ctx, CursorKey, cursor); err != nil {
		return cursor, err
	}
	return cursor, nil
}

type Payload struct {
	ID       int64          `json:"id"`
	Event    string         `json:"event"`
	At       time.Time      `json:"at"`
	Node     string         `json:"node"`
	DomainID *int64         `json:"domain_id,omitempty"`
	QueueID  *string        `json:"queue_id,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

func render(e *store.Event, node string) (string, error) {
	raw, err := json.Marshal(Payload{
		ID:       e.ID,
		Event:    e.Type,
		At:       e.CreatedAt,
		Node:     node,
		DomainID: e.DomainID,
		QueueID:  e.QueueID,
		Data:     e.Data,
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (d *Dispatcher) deliverLoop(ctx context.Context) {
	ticker := time.NewTicker(workInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.deliverDue(ctx)
		}
	}
}

func (d *Dispatcher) deliverDue(ctx context.Context) {
	due, err := d.db.DueDeliveries(ctx, time.Now().UTC(), deliverBatch)
	if err != nil {
		if ctx.Err() == nil {
			d.log.Error("webhooks: could not read pending deliveries", "error", err)
		}
		return
	}
	if len(due) == 0 {
		return
	}

	workers := d.cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	jobs := make(chan *store.Delivery)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for del := range jobs {
				d.attempt(ctx, del)
			}
		}()
	}
	for _, del := range due {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- del:
		}
	}
	close(jobs)
	wg.Wait()
}

func (d *Dispatcher) attempt(ctx context.Context, del *store.Delivery) {
	hook, err := d.db.Webhook(ctx, del.WebhookID)
	if err != nil {
		d.fail(ctx, del, 0, "the subscription no longer exists")
		return
	}
	if !hook.Enabled {
		d.fail(ctx, del, 0, "the subscription is disabled")
		return
	}

	code, err := d.post(ctx, hook, del)
	if err == nil {
		if err := d.db.MarkDeliverySucceeded(ctx, del.ID, code); err != nil {
			d.log.Error("webhooks: could not record a successful delivery", "id", del.ID, "error", err)
		}
		d.log.Debug("webhook delivered", "webhook", hook.Name, "event", del.EventType, "status", code)
		return
	}

	attempts := del.Attempts + 1
	switch {
	case !retryable(code):
		d.fail(ctx, del, code, fmt.Sprintf("%v (a %d is not retried)", err, code))
	case attempts >= d.cfg.MaxAttempts:
		d.fail(ctx, del, code, fmt.Sprintf("%v (gave up after %d attempts)", err, attempts))
	default:
		next := time.Now().UTC().Add(d.backoff(attempts))
		if err := d.db.RescheduleDelivery(ctx, del.ID, code, err.Error(), next); err != nil {
			d.log.Error("webhooks: could not schedule a retry", "id", del.ID, "error", err)
		}
		d.log.Warn("webhook delivery failed, will retry",
			"webhook", hook.Name, "event", del.EventType,
			"attempt", attempts, "next", next.Format(time.RFC3339), "error", err)
	}
}

func (d *Dispatcher) fail(ctx context.Context, del *store.Delivery, code int, reason string) {
	if err := d.db.MarkDeliveryFailed(ctx, del.ID, code, reason); err != nil {
		d.log.Error("webhooks: could not record a failed delivery", "id", del.ID, "error", err)
	}
	d.log.Error("webhook delivery abandoned",
		"id", del.ID, "event", del.EventType, "reason", reason)
}

func retryable(code int) bool {
	switch {
	case code == 0:
		return true
	case code == http.StatusRequestTimeout, code == http.StatusTooManyRequests:
		return true
	case code >= 400 && code < 500:
		return false
	default:
		return true
	}
}

func (d *Dispatcher) backoff(attempts int) time.Duration {
	base := d.cfg.RetryBase
	if base <= 0 {
		base = 30 * time.Second
	}
	max := d.cfg.RetryMax
	if max < base {
		max = base
	}

	delay := base
	for i := 1; i < attempts && delay < max; i++ {
		delay *= 2
	}
	if delay > max {
		delay = max
	}
	return delay + time.Duration(rand.Int63n(int64(delay/10)+1))
}

func (d *Dispatcher) purgeLoop(ctx context.Context) {
	retention := d.cfg.Retention
	if retention <= 0 {
		return
	}
	ticker := time.NewTicker(purgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := d.db.PurgeDeliveries(ctx, time.Now().UTC().Add(-retention))
			if err != nil {
				d.log.Warn("webhooks: could not purge the delivery log", "error", err)
			} else if n > 0 {
				d.log.Debug("webhook delivery log purged", "rows", n)
			}
		}
	}
}
