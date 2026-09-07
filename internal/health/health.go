package health

import (
	"context"
	"fmt"
	"log/slog"
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
	cfg    config.HealthConfig
	db     *store.DB
	log    *slog.Logger
	notify Notifier

	wake  chan<- int64
	count *metrics.Counters
}

func New(cfg config.HealthConfig, db *store.DB, log *slog.Logger, notify Notifier, wake chan<- int64, count *metrics.Counters) *Checker {
	return &Checker{cfg: cfg, db: db, log: log, notify: notify, wake: wake, count: count}
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

	var wg sync.WaitGroup
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		wg.Add(1)
		go func(d *store.Domain) {
			defer wg.Done()
			c.checkOne(ctx, d)
		}(d)
	}
	wg.Wait()
}

func (c *Checker) checkOne(ctx context.Context, d *store.Domain) {
	probeErr := Probe(ctx, d, c.cfg.Timeout)
	ok := probeErr == nil
	c.count.ProbesTotal.Add(1)
	if !ok {
		c.count.ProbesFailed.Add(1)
	}
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

func Probe(ctx context.Context, d *store.Domain, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := smtpclient.Dial(ctx, d, smtpclient.HelloName(d))
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Quit(); err != nil {
		return fmt.Errorf("QUIT: %w", err)
	}
	return nil
}
