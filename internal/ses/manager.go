package ses

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/xeron-be/xeron-mx/internal/store"
)

var (
	// ErrNotManaged refuses to delete an identity XeronMX did not create, or
	// one the domain only inherits from a parent.
	ErrNotManaged = errors.New("ses: identity not created by XeronMX")
	// ErrInUse refuses to delete an identity other domains send under.
	ErrInUse = errors.New("ses: identity covers other domains")
)

type Notifier interface {
	Notify(event string, payload map[string]any)
}

// BounceStatus is whether SES will accept the bounces XeronMX sends from
// MAILER-DAEMON@<smtp.hostname>, which SES requires instead of the null sender.
type BounceStatus struct {
	Sender    string     `json:"sender"`
	Identity  string     `json:"identity,omitempty"`
	Status    string     `json:"status"`
	Error     string     `json:"error,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// Manager keeps one SES identity record per configured domain: it creates the
// identity when no parent domain already covers it, follows its verification,
// and is what submission consults before accepting a sender.
type Manager struct {
	client   Client
	db       *store.DB
	log      *slog.Logger
	notify   Notifier
	region   string
	interval time.Duration
	hostname string

	// mu serialises passes, so the periodic one and a "check now" from the
	// panel never both decide to create the same identity.
	mu      sync.Mutex
	trigger chan struct{}

	bounceMu sync.RWMutex
	bounce   BounceStatus

	now func() time.Time
}

func NewManager(client Client, db *store.DB, log *slog.Logger, notify Notifier, region string, interval time.Duration, hostname string) *Manager {
	return &Manager{
		client:   client,
		db:       db,
		log:      log,
		notify:   notify,
		region:   region,
		interval: interval,
		hostname: strings.ToLower(strings.TrimSuffix(hostname, ".")),
		trigger:  make(chan struct{}, 1),
		bounce:   BounceStatus{Sender: "MAILER-DAEMON@" + hostname, Status: store.SESPending},
		now:      time.Now,
	}
}

func (m *Manager) Region() string { return m.region }

// Trigger asks for a pass soon, typically after a domain was added.
func (m *Manager) Trigger() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

func (m *Manager) Run(ctx context.Context) {
	if err := m.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
		m.log.Warn("ses: first pass failed", "error", err)
	}
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.trigger:
		}
		if err := m.ReconcileAll(ctx); err != nil && ctx.Err() == nil {
			m.log.Warn("ses: pass failed", "error", err)
		}
	}
}

func (m *Manager) ReconcileAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	domains, err := m.db.ListDomains(ctx)
	if err != nil {
		return err
	}
	cache := m.newLookups()
	for _, d := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := m.reconcile(ctx, d, cache); err != nil {
			m.log.Warn("ses: could not record the identity", "domain", d.Name, "error", err)
		}
	}
	m.checkBounceSender(ctx, cache)
	return nil
}

// Check runs a pass for one domain now and returns what it recorded.
func (m *Manager) Check(ctx context.Context, d *store.Domain) (*store.SESIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cache := m.newLookups()
	if err := m.reconcile(ctx, d, cache); err != nil {
		return nil, err
	}
	return m.db.SESIdentityFor(ctx, d.ID)
}

func (m *Manager) BounceSender() BounceStatus {
	m.bounceMu.RLock()
	defer m.bounceMu.RUnlock()
	return m.bounce
}

// Deletable says whether XeronMX may delete the domain's SES identity, and if
// not, why: only one it created itself, and that no other domain inherits.
func (m *Manager) Deletable(ctx context.Context, d *store.Domain) (*store.SESIdentity, []string, error) {
	row, err := m.db.SESIdentityFor(ctx, d.ID)
	if err != nil {
		return nil, nil, err
	}
	if !row.Managed || row.Inherited || row.Identity != d.Name {
		return row, nil, ErrNotManaged
	}
	deps, err := m.db.SESDependents(ctx, row.Identity, d.ID)
	if err != nil {
		return row, nil, err
	}
	if len(deps) > 0 {
		return row, deps, ErrInUse
	}
	return row, nil, nil
}

// DeleteIdentity removes the domain's identity from SES. It is only ever
// called on an explicit request, as part of deleting the domain.
func (m *Manager) DeleteIdentity(ctx context.Context, d *store.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	row, _, err := m.Deletable(ctx, d)
	if err != nil {
		return err
	}
	if err := m.client.DeleteIdentity(ctx, row.Identity); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := m.db.DeleteSESIdentity(ctx, d.ID); err != nil {
		return err
	}
	m.log.Info("ses: identity deleted", "identity", row.Identity)
	return nil
}

type lookup struct {
	id  *Identity
	err error
}

// lookups caches GetEmailIdentity for one pass, so a hundred subdomains of the
// same parent cost one call, not a hundred.
type lookups struct {
	client Client
	seen   map[string]lookup
}

func (m *Manager) newLookups() *lookups {
	return &lookups{client: m.client, seen: map[string]lookup{}}
}

func (l *lookups) get(ctx context.Context, name string) (*Identity, error) {
	if r, ok := l.seen[name]; ok {
		return r.id, r.err
	}
	id, err := l.client.GetIdentity(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		// Do not cache transport errors: the next domain may get through.
		return nil, err
	}
	l.seen[name] = lookup{id, err}
	return id, err
}

func (l *lookups) put(name string, id *Identity) { l.seen[name] = lookup{id: id} }

func (m *Manager) reconcile(ctx context.Context, d *store.Domain, cache *lookups) error {
	row, err := m.db.SESIdentityFor(ctx, d.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		row = nil
	case err != nil:
		return err
	}

	next := m.resolve(ctx, d, row, cache)
	now := m.now().UTC()
	next.CheckedAt = &now
	if err := m.db.SaveSESIdentity(ctx, next); err != nil {
		return err
	}

	prev := ""
	if row != nil {
		prev = row.Status
	}
	if next.Status != prev {
		m.statusChanged(ctx, d, next)
	}
	return nil
}

// resolve decides which identity covers d and in which state it is. It never
// fails: an SES error is recorded on the row, keeping the last known status so
// that a passing outage of the SES API does not stop mail that was flowing.
func (m *Manager) resolve(ctx context.Context, d *store.Domain, row *store.SESIdentity, cache *lookups) *store.SESIdentity {
	failed := func(err error) *store.SESIdentity {
		if row != nil {
			kept := *row
			kept.LastError = err.Error()
			return &kept
		}
		return &store.SESIdentity{DomainID: d.ID, Identity: "", Status: store.SESError, LastError: err.Error()}
	}

	if row != nil && row.Identity != "" {
		id, err := cache.get(ctx, row.Identity)
		switch {
		case err == nil && !(row.Inherited && id.Status == StatusFailed):
			return fromIdentity(d.ID, id, row.Inherited, row.Managed)
		case err == nil, errors.Is(err, ErrNotFound):
			// The parent failed, or the identity is gone from SES: look again.
		default:
			return failed(err)
		}
	}

	own, err := cache.get(ctx, d.Name)
	switch {
	case err == nil:
		managed := row != nil && row.Identity == d.Name && !row.Inherited && row.Managed
		return fromIdentity(d.ID, own, false, managed)
	case !errors.Is(err, ErrNotFound):
		return failed(err)
	}

	for _, parent := range parents(d.Name) {
		id, err := cache.get(ctx, parent)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return failed(err)
		}
		if id.Status != StatusFailed {
			// A verified domain covers all of its subdomains in SES. A pending
			// one will, once verified: creating a second identity meanwhile would
			// only mean three more CNAME records to publish for nothing.
			return fromIdentity(d.ID, id, true, false)
		}
	}

	created, err := m.client.CreateIdentity(ctx, d.Name)
	if errors.Is(err, ErrAlreadyExists) {
		// Another node, or a person, created it between our lookup and now.
		got, gerr := m.client.GetIdentity(ctx, d.Name)
		if gerr != nil {
			return failed(gerr)
		}
		cache.put(d.Name, got)
		return fromIdentity(d.ID, got, false, false)
	}
	if err != nil {
		return failed(err)
	}
	m.log.Info("ses: identity created", "domain", d.Name, "status", created.Status)
	cache.put(d.Name, created)
	return fromIdentity(d.ID, created, false, true)
}

func fromIdentity(domainID int64, id *Identity, inherited, managed bool) *store.SESIdentity {
	out := &store.SESIdentity{
		DomainID:  domainID,
		Identity:  id.Name,
		Inherited: inherited,
		Managed:   managed,
		Status:    LocalStatus(id),
	}
	if !inherited {
		out.DKIMTokens = id.DKIMTokens
	}
	return out
}

// LocalStatus maps SES's verification state onto XeronMX's three.
func LocalStatus(id *Identity) string {
	switch {
	case id.VerifiedForSending || id.Status == StatusSuccess:
		return store.SESVerified
	case id.Status == StatusFailed:
		return store.SESFailed
	default:
		// PENDING, NOT_STARTED and TEMPORARY_FAILURE (SES could not read the
		// DNS for now and will try again) all end up verified or failed.
		return store.SESPending
	}
}

func (m *Manager) statusChanged(ctx context.Context, d *store.Domain, s *store.SESIdentity) {
	var event string
	switch s.Status {
	case store.SESVerified:
		event = store.EventSESVerified
	case store.SESFailed:
		event = store.EventSESFailed
	default:
		return
	}
	data := map[string]any{"domain": d.Name, "identity": s.Identity, "inherited": s.Inherited}
	id := d.ID
	if err := m.db.RecordEvent(ctx, &store.Event{Type: event, DomainID: &id, Data: data}); err != nil {
		m.log.Warn("ses: could not record the event", "error", err)
	}
	if m.notify != nil {
		m.notify.Notify(event, data)
	}
	m.log.Info("ses: identity status changed", "domain", d.Name, "identity", s.Identity, "status", s.Status)
}

func (m *Manager) checkBounceSender(ctx context.Context, cache *lookups) {
	now := m.now().UTC()
	st := BounceStatus{Sender: "MAILER-DAEMON@" + m.hostname, CheckedAt: &now, Status: store.SESFailed}

	for _, name := range append([]string{m.hostname}, parents(m.hostname)...) {
		if !strings.Contains(name, ".") {
			break
		}
		id, err := cache.get(ctx, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			st.Status = store.SESError
			st.Error = err.Error()
			break
		}
		st.Identity = name
		st.Status = LocalStatus(id)
		break
	}
	if st.Identity == "" && st.Status == store.SESFailed {
		st.Error = fmt.Sprintf("no SES identity covers %s", m.hostname)
	}

	m.bounceMu.Lock()
	m.bounce = st
	m.bounceMu.Unlock()
}

// parents lists the parent domains of name up to its registrable domain,
// nearest first: a.b.example.co.uk gives b.example.co.uk, example.co.uk.
func parents(name string) []string {
	top, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || top == name {
		return nil
	}
	var out []string
	rest := name
	for {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return out
		}
		rest = rest[i+1:]
		out = append(out, rest)
		if rest == top {
			return out
		}
	}
}
