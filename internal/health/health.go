package health

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type Notifier interface {
	Notify(event string, payload map[string]any)
}

type Checker struct {
	cfg          config.HealthConfig
	allowPrivate bool
	db           *store.DB
	log          *slog.Logger
	notify       Notifier

	wake  chan<- int64
	count *metrics.Counters
}

func New(cfg config.HealthConfig, allowPrivate bool, db *store.DB, log *slog.Logger, notify Notifier, wake chan<- int64, count *metrics.Counters) *Checker {
	return &Checker{cfg: cfg, allowPrivate: allowPrivate, db: db, log: log, notify: notify, wake: wake, count: count}
}

func (c *Checker) Run(ctx context.Context) {
	c.log.Info("health checker started",
		"interval", c.cfg.Interval,
		"failure_threshold", c.cfg.FailureThreshold,
		"success_threshold", c.cfg.SuccessThreshold)

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	c.checkAll(ctx)
	for {
		select {
		case <-ctx.Done():
			c.log.Info("health checker stopped")
			return
		case <-ticker.C:
			c.checkAll(ctx)
		}
	}
}

func (c *Checker) checkAll(ctx context.Context) {
	domains, err := c.db.ListDomains(ctx)
	if err != nil {
		c.log.Error("health: list domains failed", "error", err)
		return
	}

	var order []string
	groups := map[string][]*store.Domain{}
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		key := primaryKey(d)
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], d)
	}

	var wg sync.WaitGroup
	for _, key := range order {
		wg.Add(1)
		go func(sharing []*store.Domain) {
			defer wg.Done()
			probeErr := c.probe(ctx, sharing[0])
			for _, d := range sharing {
				c.apply(ctx, d, probeErr)
			}
		}(groups[key])
	}
	wg.Wait()
}

func primaryKey(d *store.Domain) string {
	return fmt.Sprintf("%s|%d|%s", strings.ToLower(strings.TrimSuffix(d.PrimaryHost, ".")), d.PrimaryPort, d.PrimaryTLS)
}

func (c *Checker) probe(ctx context.Context, d *store.Domain) error {
	probeErr := Probe(ctx, d, c.cfg.Timeout, c.allowPrivate)
	c.count.ProbesTotal.Add(1)
	if probeErr != nil {
		c.count.ProbesFailed.Add(1)
	}
	return probeErr
}

func (c *Checker) apply(ctx context.Context, d *store.Domain, probeErr error) {
	ok := probeErr == nil
	msg := ""
	if probeErr != nil {
		msg = probeErr.Error()
	}

	flipped, isUp, err := c.db.RecordProbe(ctx, d.ID, ok, msg,
		c.cfg.FailureThreshold, c.cfg.SuccessThreshold, time.Now().UTC())
	if err != nil {
		c.log.Error("health: record probe failed", "domain", d.Name, "error", err)
		return
	}
	if !flipped {
		return
	}

	event := store.EventPrimaryDown
	if isUp {
		event = store.EventPrimaryUp
	}
	c.log.Info("primary state changed", "domain", d.Name, "up", isUp, "error", msg)

	domainID := d.ID
	if err := c.db.RecordEvent(ctx, &store.Event{
		Type:     event,
		DomainID: &domainID,
		Data:     map[string]any{"host": d.PrimaryHost, "port": d.PrimaryPort, "error": msg},
	}); err != nil {
		c.log.Warn("health: event not recorded", "error", err)
	}
	if c.notify != nil {
		c.notify.Notify(event, map[string]any{
			"domain": d.Name, "up": isUp, "error": msg,
		})
	}

	if isUp {
		if n, err := c.db.RetryDomainNow(ctx, d.ID, time.Now().UTC()); err != nil {
			c.log.Warn("health: could not pull retries forward", "domain", d.Name, "error", err)
		} else if n > 0 {
			c.log.Info("primary recovered, queue pulled forward", "domain", d.Name, "messages", n)
		}
		if c.wake != nil {
			select {
			case c.wake <- d.ID:
			default:
			}
		}
	}
}

func Probe(ctx context.Context, d *store.Domain, timeout time.Duration, allowPrivate bool) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := smtpclient.Dial(ctx, d, smtpclient.HelloName(d), smtpclient.PublicOnly(!allowPrivate))
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Quit(); err != nil {
		return fmt.Errorf("QUIT: %w", err)
	}
	return nil
}
