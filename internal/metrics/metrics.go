package metrics

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/version"
)

type Counters struct {
	MessagesReceived  atomic.Int64
	MessagesRejected  atomic.Int64
	MessagesDelivered atomic.Int64
	MessagesDeferred  atomic.Int64
	MessagesFailed    atomic.Int64
	MessagesExpired   atomic.Int64
	BytesReceived     atomic.Int64
	SMTPConnections   atomic.Int64
	ProbesTotal       atomic.Int64
	ProbesFailed      atomic.Int64
}

type Collector struct {
	db       *store.DB
	counters *Counters
	log      *slog.Logger
	token    string
	start    time.Time
}

func New(db *store.DB, counters *Counters, token string, log *slog.Logger) *Collector {
	return &Collector{db: db, counters: counters, token: token, log: log, start: time.Now()}
}

func (c *Collector) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.token != "" {

			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") || subtleCompare(strings.TrimPrefix(auth, "Bearer "), c.token) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := c.Write(r.Context(), w); err != nil {
			c.log.Error("metrics render failed", "error", err)
		}
	}
}

func (c *Collector) Write(ctx context.Context, w io.Writer) error {
	b := &builder{w: w}

	b.gauge("xeronmx_build_info", "Build information, always 1.", 1,
		label{"version", version.Version}, label{"commit", version.Commit})
	b.gauge("xeronmx_uptime_seconds", "Seconds since the process started.",
		time.Since(c.start).Seconds())

	b.counter("xeronmx_messages_received_total", "Messages accepted onto the spool.",
		float64(c.counters.MessagesReceived.Load()))
	b.counter("xeronmx_messages_rejected_total", "Messages refused at SMTP time.",
		float64(c.counters.MessagesRejected.Load()))
	b.counter("xeronmx_messages_delivered_total", "Messages the primary accepted.",
		float64(c.counters.MessagesDelivered.Load()))
	b.counter("xeronmx_messages_deferred_total", "Delivery attempts that failed temporarily.",
		float64(c.counters.MessagesDeferred.Load()))
	b.counter("xeronmx_messages_failed_total", "Messages permanently rejected by the primary.",
		float64(c.counters.MessagesFailed.Load()))
	b.counter("xeronmx_messages_expired_total", "Messages that outlived their retention undelivered.",
		float64(c.counters.MessagesExpired.Load()))
	b.counter("xeronmx_bytes_received_total", "Bytes of message body accepted.",
		float64(c.counters.BytesReceived.Load()))
	b.counter("xeronmx_smtp_connections_total", "Inbound SMTP connections.",
		float64(c.counters.SMTPConnections.Load()))
	b.counter("xeronmx_probes_total", "Primary health probes attempted.",
		float64(c.counters.ProbesTotal.Load()))
	b.counter("xeronmx_probes_failed_total", "Primary health probes that failed.",
		float64(c.counters.ProbesFailed.Load()))

	stats, err := c.db.Stats(ctx)
	if err != nil {
		return err
	}
	b.gauge("xeronmx_queue_pending", "Messages waiting for the primary.", float64(stats.Pending))
	b.gauge("xeronmx_queue_pending_bytes", "Bytes waiting on the spool.", float64(stats.PendingBytes))
	b.gauge("xeronmx_queue_rows", "Rows in the queue table, delivered history included.", float64(stats.Total))

	oldest, err := c.db.OldestQueued(ctx)
	if err != nil {
		return err
	}
	b.gauge("xeronmx_queue_oldest_seconds",
		"Age of the longest-waiting message. Zero when the queue is empty.", oldest.Seconds())

	breakdown, err := c.db.Breakdown(ctx)
	if err != nil {
		return err
	}
	b.header("xeronmx_queue_messages", "gauge", "Messages by domain and status.")
	for _, row := range breakdown {
		b.sample("xeronmx_queue_messages", float64(row.Count),
			label{"domain", row.DomainName}, label{"status", string(row.Status)})
	}

	health, err := c.db.AllDomainHealth(ctx)
	if err != nil {
		return err
	}
	b.header("xeronmx_primary_up", "gauge", "1 when the domain primary answered its last probes.")
	for _, dh := range health {
		up := 0.0
		if dh.Status != nil && dh.Status.IsUp {
			up = 1
		}
		b.sample("xeronmx_primary_up", up, label{"domain", dh.Domain.Name})
	}
	b.header("xeronmx_domain_enabled", "gauge", "1 when XeronMX accepts mail for the domain.")
	for _, dh := range health {
		enabled := 0.0
		if dh.Domain.Enabled {
			enabled = 1
		}
		b.sample("xeronmx_domain_enabled", enabled, label{"domain", dh.Domain.Name})
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	b.gauge("xeronmx_goroutines", "Goroutines currently running.", float64(runtime.NumGoroutine()))
	b.gauge("xeronmx_memory_heap_bytes", "Heap bytes in use.", float64(mem.HeapAlloc))

	return b.err
}

type label struct{ name, value string }

type builder struct {
	w    io.Writer
	err  error
	seen map[string]bool
}

func (b *builder) printf(format string, args ...any) {
	if b.err != nil {
		return
	}
	_, b.err = fmt.Fprintf(b.w, format, args...)
}

func (b *builder) header(name, typ, help string) {
	if b.seen == nil {
		b.seen = make(map[string]bool)
	}
	if b.seen[name] {
		return
	}
	b.seen[name] = true
	b.printf("# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (b *builder) gauge(name, help string, value float64, labels ...label) {
	b.header(name, "gauge", help)
	b.sample(name, value, labels...)
}

func (b *builder) counter(name, help string, value float64, labels ...label) {
	b.header(name, "counter", help)
	b.sample(name, value, labels...)
}

func (b *builder) sample(name string, value float64, labels ...label) {
	if len(labels) == 0 {
		b.printf("%s %g\n", name, value)
		return
	}

	sort.Slice(labels, func(i, j int) bool { return labels[i].name < labels[j].name })

	parts := make([]string, 0, len(labels))
	for _, l := range labels {

		parts = append(parts, fmt.Sprintf(`%s="%s"`, l.name, escapeLabel(l.value)))
	}
	b.printf("%s{%s} %g\n", name, strings.Join(parts, ","), value)
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func subtleCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
