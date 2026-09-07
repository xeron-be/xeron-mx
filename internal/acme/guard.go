package acme

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	guardBurst = 120

	guardRefill      = 2 * time.Minute
	guardWarnAfter   = 5 * time.Minute
	guardMaxWaitStep = 30 * time.Second
)

type issuanceGuard struct {
	log *slog.Logger
	rt  http.RoundTripper

	mu       sync.Mutex
	tokens   int
	lastFill time.Time
	warnedAt time.Time
}

func newIssuanceGuard(rt http.RoundTripper, log *slog.Logger) *issuanceGuard {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &issuanceGuard{
		log:      log,
		rt:       rt,
		tokens:   guardBurst,
		lastFill: time.Now(),
	}
}

func (g *issuanceGuard) take(now time.Time) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	if earned := int(now.Sub(g.lastFill) / guardRefill); earned > 0 {
		g.tokens += earned
		if g.tokens > guardBurst {
			g.tokens = guardBurst
		}
		g.lastFill = g.lastFill.Add(time.Duration(earned) * guardRefill)
	}

	if g.tokens > 0 {
		g.tokens--
		return 0
	}

	wait := guardRefill - now.Sub(g.lastFill)
	if wait < 0 {
		wait = 0
	}
	if wait > guardMaxWaitStep {
		wait = guardMaxWaitStep
	}

	if now.Sub(g.warnedAt) > guardWarnAfter {
		g.warnedAt = now
		g.log.Error("slowing down requests to the certificate authority",
			"why", "this instance is asking for certificates far faster than any renewal needs, "+
				"which usually means http.acme.renew_before is longer than the lifetime of the "+
				"certificates this CA issues, so every new certificate is already due for renewal",
			"check", "compare renew_before with the certificate's own validity period",
			"without_this", "a real CA would refuse the account long before anyone noticed")
	}
	return wait
}

func (g *issuanceGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if wait := g.take(time.Now()); wait > 0 {
		select {
		case <-req.Context().Done():
			return nil, fmt.Errorf("acme: gave up waiting to contact the CA: %w", req.Context().Err())
		case <-time.After(wait):
		}
	}
	return g.rt.RoundTrip(req)
}
