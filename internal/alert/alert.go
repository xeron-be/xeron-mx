package alert

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

const queueDepth = 64

type Alert struct {
	Key      string         `json:"key"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
	Host     string         `json:"host"`
	At       time.Time      `json:"at"`
	Data     map[string]any `json:"data,omitempty"`
}

type Alerter struct {
	cfg    config.AlertConfig
	log    *slog.Logger
	host   string
	client *http.Client

	queue chan Alert

	mu       sync.Mutex
	grace    map[string]*time.Timer
	fired    map[string]bool
	lastSent map[string]time.Time
}

func New(cfg config.AlertConfig, hostname string, log *slog.Logger) *Alerter {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "xeronmx"
		}
	}
	timeout := cfg.Webhook.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Alerter{
		cfg:      cfg,
		log:      log,
		host:     hostname,
		client:   &http.Client{Timeout: timeout},
		queue:    make(chan Alert, queueDepth),
		grace:    make(map[string]*time.Timer),
		fired:    make(map[string]bool),
		lastSent: make(map[string]time.Time),
	}
}

func (a *Alerter) Enabled() bool {
	return a.cfg.Enabled && (a.cfg.Webhook.URL != "" || len(a.cfg.Email.To) > 0)
}

func (a *Alerter) Notify(event string, payload map[string]any) {
	if !a.Enabled() {
		return
	}

	switch event {
	case store.EventPrimaryDown:
		a.primaryDown(payload)
	case store.EventPrimaryUp:
		a.primaryUp(payload)
	case store.EventQueueFull:
		if reason, _ := payload["reason"].(string); reason == "domain_cap" {
			domain, _ := payload["domain"].(string)
			a.emit(Alert{
				Key:      "queue_full:" + domain,
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("The queue for %s is full and its mail is being refused", domain),
				Detail: fmt.Sprintf("%s has reached its max_queue_messages ceiling, so XeronMX answers 452 "+
					"to new mail for it. Senders will retry, and other domains are unaffected. "+
					"Bring the primary back or raise the domain's ceiling.", domain),
				Data: payload,
			})
			return
		}
		a.emit(Alert{
			Key:      "queue_full",
			Severity: SeverityCritical,
			Title:    "The spool is full and mail is being refused",
			Detail: "XeronMX has reached a configured queue ceiling and is answering 452. " +
				"Senders will hold their mail and retry, but the safety net is no longer catching anything. " +
				"Drain the queue or raise queue.max_messages / queue.max_bytes.",
			Data: payload,
		})
	case store.EventMailExpired:
		a.emit(Alert{
			Key:      "mail_expired",
			Severity: SeverityCritical,
			Title:    "A message was given up on before the primary accepted it",
			Detail: "A queued message reached the end of its retention without being delivered. " +
				"This is the one outcome XeronMX exists to prevent, so it is worth understanding why.",
			Data: payload,
		})
	case store.EventMailFailed:
		if reason, _ := payload["reason"].(string); reason == "body unreadable" {
			a.emit(Alert{
				Key:      "mail_lost",
				Severity: SeverityCritical,
				Title:    "A queued message could not be read back from the spool",
				Detail: "The message body is missing or does not decrypt, so it cannot be delivered. " +
					"This is data lost on this machine: check the disk and the master key.",
				Data: payload,
			})
			return
		}
		a.emit(Alert{
			Key:      "mail_failed",
			Severity: SeverityWarning,
			Title:    "The primary permanently refused a message or a recipient",
			Detail: "The primary answered 5xx, so XeronMX will not retry. The sender is told with a " +
				"delivery status notification when its address could be authenticated; otherwise " +
				"nobody but this alert knows the message was not delivered.",
			Data: payload,
		})
	}
}

type StatusSource interface {
	ListDomains(ctx context.Context) ([]*store.Domain, error)
	PrimaryStatusFor(ctx context.Context, domainID int64) (*store.PrimaryStatus, error)
}

func (a *Alerter) Resume(ctx context.Context, db StatusSource) {
	if !a.Enabled() {
		return
	}
	domains, err := db.ListDomains(ctx)
	if err != nil {
		a.log.Warn("could not read the primaries' state at startup", "error", err)
		return
	}
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		st, err := db.PrimaryStatusFor(ctx, d.ID)
		if err != nil || st.IsUp || st.LastCheck == nil {
			continue
		}
		since := *st.LastCheck
		if st.LastDown != nil {
			since = *st.LastDown
		}
		a.log.Info("primary already down at startup", "domain", d.Name, "since", since)
		a.primaryDownSince(since, map[string]any{
			"domain": d.Name, "up": false, "error": st.LastError, "since": since,
		})
	}
}

func (a *Alerter) primaryDown(payload map[string]any) {
	a.primaryDownSince(time.Now(), payload)
}

func (a *Alerter) primaryDownSince(since time.Time, payload map[string]any) {
	domain, _ := payload["domain"].(string)
	if domain == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, waiting := a.grace[domain]; waiting {
		return
	}

	fire := func() {
		a.mu.Lock()
		delete(a.grace, domain)
		a.fired[domain] = true
		a.mu.Unlock()

		a.emit(Alert{
			Key:      "primary_down:" + domain,
			Severity: SeverityWarning,
			Title:    fmt.Sprintf("The primary for %s is not answering", domain),
			Detail: fmt.Sprintf(
				"XeronMX is accepting and holding mail for %s. Nothing is lost while this lasts, "+
					"but the queue will keep growing until the primary comes back.", domain),
			Data: payload,
		})
	}

	remaining := a.cfg.PrimaryDownAfter - time.Since(since)
	if remaining <= 0 {
		go fire()
		return
	}
	a.grace[domain] = time.AfterFunc(remaining, fire)
}

func (a *Alerter) primaryUp(payload map[string]any) {
	domain, _ := payload["domain"].(string)
	if domain == "" {
		return
	}

	a.mu.Lock()
	if t, waiting := a.grace[domain]; waiting {
		t.Stop()
		delete(a.grace, domain)
	}
	announced := a.fired[domain]
	delete(a.fired, domain)
	delete(a.lastSent, "primary_down:"+domain)
	a.mu.Unlock()

	if !announced {
		return
	}
	a.emit(Alert{
		Key:      "primary_up:" + domain,
		Severity: SeverityInfo,
		Title:    fmt.Sprintf("The primary for %s is answering again", domain),
		Detail:   fmt.Sprintf("XeronMX is delivering what it held for %s, oldest first.", domain),
		Data:     payload,
	})
}

func (a *Alerter) emit(al Alert) {
	if al.At.IsZero() {
		al.At = time.Now().UTC()
	}
	al.Host = a.host

	if !a.shouldSend(al.Key) {
		return
	}

	select {
	case a.queue <- al:
	default:
		a.log.Warn("alert dropped: the delivery queue is full", "key", al.Key)
	}
}

func (a *Alerter) shouldSend(key string) bool {
	interval := a.cfg.MinInterval
	if interval <= 0 {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if last, ok := a.lastSent[key]; ok && time.Since(last) < interval {
		return false
	}
	a.lastSent[key] = time.Now()
	return true
}

func (a *Alerter) Run(ctx context.Context) {
	if !a.Enabled() {
		return
	}
	a.log.Info("alerting enabled",
		"webhook", a.cfg.Webhook.URL != "",
		"email", len(a.cfg.Email.To) > 0,
		"primary_down_after", a.cfg.PrimaryDownAfter.String())

	for {
		select {
		case <-ctx.Done():
			a.stopTimers()
			return
		case al := <-a.queue:
			a.deliver(ctx, al)
		}
	}
}

func (a *Alerter) stopTimers() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for domain, t := range a.grace {
		t.Stop()
		delete(a.grace, domain)
	}
}

func (a *Alerter) deliver(ctx context.Context, al Alert) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if a.cfg.Webhook.URL != "" {
		if err := a.postWebhook(ctx, al); err != nil {
			a.log.Error("webhook alert failed", "key", al.Key, "error", err)
		} else {
			a.log.Info("alert sent", "channel", "webhook", "key", al.Key)
		}
	}
	if len(a.cfg.Email.To) > 0 {
		if err := a.sendEmail(ctx, al); err != nil {
			a.log.Error("email alert failed", "key", al.Key, "error", err)
		} else {
			a.log.Info("alert sent", "channel", "email", "key", al.Key)
		}
	}
}

func describe(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s: %v\r\n", k, data[k])
	}
	return b.String()
}
