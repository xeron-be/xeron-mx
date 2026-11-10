package ses

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	ReasonBounces    = "bounces"
	ReasonComplaints = "complaints"
	ReasonManual     = "manual"
)

const (
	LevelOK        = "ok"
	LevelWarning   = "warning"
	LevelSuspended = "suspended"
)

type MonitorStatus struct {
	QueueURL   string     `json:"queue_url"`
	LastPollAt *time.Time `json:"last_poll_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	Recorded   int64      `json:"recorded"`
}

type Monitor struct {
	queue  Queue
	db     *store.DB
	log    *slog.Logger
	notify Notifier
	prot   config.SendingProtection

	mu     sync.RWMutex
	status MonitorStatus

	now   func() time.Time
	sleep func(context.Context, time.Duration)
}

func NewMonitor(queue Queue, queueURL string, db *store.DB, log *slog.Logger, notify Notifier, prot config.SendingProtection) *Monitor {
	return &Monitor{
		queue: queue, db: db, log: log, notify: notify, prot: prot,
		status: MonitorStatus{QueueURL: queueURL},
		now:    time.Now,
		sleep: func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		},
	}
}

func (m *Monitor) Protection() config.SendingProtection { return m.prot }

func (m *Monitor) Status() MonitorStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Monitor) Run(ctx context.Context) {
	m.log.Info("ses events: reading bounces and complaints", "queue", m.status.QueueURL)
	backoff := 5 * time.Second
	lastPrune := time.Time{}
	for ctx.Err() == nil {
		if m.now().Sub(lastPrune) > 6*time.Hour {
			m.prune(ctx)
			lastPrune = m.now()
		}
		if _, err := m.Poll(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			m.log.Warn("ses events: could not read the queue", "error", err, "retry_in", backoff)
			m.sleep(ctx, backoff)
			backoff = min(backoff*2, 5*time.Minute)
			continue
		}
		backoff = 5 * time.Second
	}
}

func (m *Monitor) Poll(ctx context.Context) (int, error) {
	msgs, err := m.queue.Receive(ctx)
	now := m.now().UTC()
	m.mu.Lock()
	m.status.LastPollAt = &now
	if err != nil {
		m.status.LastError = err.Error()
	} else {
		m.status.LastError = ""
	}
	m.mu.Unlock()
	if err != nil {
		return 0, err
	}

	var done []string
	touched := map[int64]*store.Domain{}
	recorded := 0
	for _, msg := range msgs {
		n, ok := m.record(ctx, msg, touched)
		recorded += n
		if ok {
			done = append(done, msg.ReceiptHandle)
		}
	}
	for _, d := range touched {
		if err := m.Evaluate(ctx, d); err != nil {
			m.log.Error("ses events: could not evaluate the domain", "domain", d.Name, "error", err)
		}
	}
	if len(done) > 0 {
		if err := m.queue.Delete(ctx, done); err != nil {
			m.log.Warn("ses events: could not delete processed messages; they will be read again", "error", err)
		}
	}
	m.mu.Lock()
	m.status.Recorded += int64(recorded)
	m.mu.Unlock()
	return recorded, nil
}

func (m *Monitor) record(ctx context.Context, msg QueueMessage, touched map[int64]*store.Domain) (int, bool) {
	feedback, err := ParseEvent(msg.Body)
	if err != nil {
		m.log.Warn("ses events: unreadable message dropped", "message_id", msg.ID, "error", err)
		return 0, true
	}
	n := 0
	for _, f := range feedback {
		d := m.domainOf(ctx, f.Sender)
		if d == nil {
			continue
		}
		added, err := m.db.AddFeedback(ctx, &store.SendingFeedback{
			DomainID: d.ID, Kind: f.Kind, Sender: f.Sender, Recipient: f.Recipient,
			FeedbackID: f.FeedbackID, SESMessageID: f.SESMessageID, Detail: f.Detail, OccurredAt: f.At,
		})
		if err != nil {
			m.log.Error("ses events: could not record feedback", "error", err)
			return n, false
		}
		if added {
			n++
			touched[d.ID] = d
			m.log.Info("ses events: "+f.Kind+" recorded", "domain", d.Name, "recipient", f.Recipient)
		}
	}
	return n, true
}

func (m *Monitor) domainOf(ctx context.Context, sender string) *store.Domain {
	at := strings.LastIndex(sender, "@")
	if at <= 0 || strings.EqualFold(sender[:at], "mailer-daemon") {
		return nil
	}
	d, err := m.db.DomainByName(ctx, sender[at+1:])
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			m.log.Error("ses events: domain lookup failed", "error", err)
		}
		return nil
	}
	return d
}

func (m *Monitor) Window(ctx context.Context, d *store.Domain) (*store.SendingWindow, *store.SendingState, error) {
	st, err := m.db.SendingStateFor(ctx, d.ID)
	if err != nil {
		return nil, nil, err
	}
	since := m.now().UTC().Add(-m.prot.Window)
	if st.CountedSince != nil && st.CountedSince.After(since) {
		since = *st.CountedSince
	}
	w, err := m.db.SendingStats(ctx, d.ID, since)
	if err != nil {
		return nil, nil, err
	}
	return w, st, nil
}

func (m *Monitor) Evaluate(ctx context.Context, d *store.Domain) error {
	w, st, err := m.Window(ctx, d)
	if err != nil {
		return err
	}
	if st.Suspended() {
		return nil
	}
	level, reason := Assess(m.prot, w)
	data := m.eventData(d, w, reason)
	now := m.now().UTC()

	switch level {
	case LevelSuspended:
		changed, err := m.db.SuspendSending(ctx, d.ID, reason, "auto", now)
		if err != nil || !changed {
			return err
		}
		m.log.Warn("sending suspended: the domain is putting the SES account at risk",
			"domain", d.Name, "reason", reason, "sent", w.Sent, "bounces", w.Bounces, "complaints", w.Complaints)
		m.announce(ctx, d, store.EventSendingSuspended, data)
	case LevelWarning:
		if st.WarnedAt != nil && !st.WarnedAt.Before(w.Since) {
			return nil
		}
		if err := m.db.MarkSendingWarned(ctx, d.ID, now); err != nil {
			return err
		}
		m.log.Warn("sending reputation warning", "domain", d.Name, "reason", reason,
			"sent", w.Sent, "bounces", w.Bounces, "complaints", w.Complaints)
		m.announce(ctx, d, store.EventSendingWarning, data)
	}
	return nil
}

func (m *Monitor) eventData(d *store.Domain, w *store.SendingWindow, reason string) map[string]any {
	return map[string]any{
		"domain":         d.Name,
		"reason":         reason,
		"sent":           w.Sent,
		"bounces":        w.Bounces,
		"complaints":     w.Complaints,
		"bounce_percent": BouncePercent(w),
		"window":         m.prot.Window.String(),
	}
}

func (m *Monitor) announce(ctx context.Context, d *store.Domain, event string, data map[string]any) {
	id := d.ID
	if err := m.db.RecordEvent(ctx, &store.Event{Type: event, DomainID: &id, Data: data}); err != nil {
		m.log.Warn("ses events: could not record the event", "error", err)
	}
	if m.notify != nil {
		m.notify.Notify(event, data)
	}
}

func (m *Monitor) prune(ctx context.Context) {
	keep := max(m.prot.Window, 30*24*time.Hour)
	if err := m.db.PruneSending(ctx, m.now().Add(-keep)); err != nil {
		m.log.Warn("ses events: prune failed", "error", err)
	}
}

func BouncePercent(w *store.SendingWindow) float64 {
	base := max(w.Sent, w.Bounces)
	if base == 0 {
		return 0
	}
	return math.Round(1000*float64(w.Bounces)/float64(base)) / 10
}

func Assess(p config.SendingProtection, w *store.SendingWindow) (level, reason string) {
	rate := 0.0
	if base := max(w.Sent, w.Bounces); base > 0 {
		rate = 100 * float64(w.Bounces) / float64(base)
	}
	switch {
	case w.Complaints >= int64(p.SuspendComplaints):
		return LevelSuspended, ReasonComplaints
	case w.Bounces >= int64(p.SuspendMinBounces) && rate >= p.SuspendBouncePercent:
		return LevelSuspended, ReasonBounces
	case w.Complaints >= int64(p.WarnComplaints):
		return LevelWarning, ReasonComplaints
	case w.Bounces >= int64(p.WarnMinBounces) && rate >= p.WarnBouncePercent:
		return LevelWarning, ReasonBounces
	}
	return LevelOK, ""
}

func (m *Monitor) Suspend(ctx context.Context, d *store.Domain, by string) (bool, error) {
	return SuspendDomain(ctx, m.db, d, by, m.now())
}

func SuspendDomain(ctx context.Context, db *store.DB, d *store.Domain, by string, at time.Time) (bool, error) {
	changed, err := db.SuspendSending(ctx, d.ID, ReasonManual, by, at)
	if err != nil {
		return false, fmt.Errorf("suspend %s: %w", d.Name, err)
	}
	return changed, nil
}
