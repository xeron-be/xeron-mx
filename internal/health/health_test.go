package health

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type primary struct {
	host string
	port int

	refuse atomic.Bool
	silent atomic.Bool
}

func startPrimary(t *testing.T) *primary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	p := &primary{host: "127.0.0.1", port: addr.Port}

	stop := make(chan struct{})
	var conns sync.WaitGroup
	t.Cleanup(func() {
		close(stop)
		ln.Close()
		conns.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				defer c.Close()
				p.serve(c, stop)
			}()
		}
	}()
	return p
}

func (p *primary) serve(c net.Conn, stop <-chan struct{}) {
	if p.silent.Load() {
		<-stop
		return
	}
	if p.refuse.Load() {
		fmt.Fprint(c, "421 4.3.2 maintenance\r\n")
		return
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(c, "220 primary ESMTP\r\n")
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch verb, _, _ := strings.Cut(strings.TrimSpace(line), " "); strings.ToUpper(verb) {
		case "EHLO", "HELO":
			fmt.Fprint(c, "250 primary\r\n")
		case "QUIT":
			fmt.Fprint(c, "221 bye\r\n")
			return
		default:
			fmt.Fprint(c, "502 not implemented\r\n")
		}
	}
}

type notification struct {
	event   string
	payload map[string]any
}

type recorder struct {
	mu   sync.Mutex
	sent []notification
}

func (r *recorder) Notify(event string, payload map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, notification{event, payload})
}

func (r *recorder) events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, n := range r.sent {
		out = append(out, n.event)
	}
	return out
}

type harness struct {
	t       *testing.T
	db      *store.DB
	checker *Checker
	notify  *recorder
	wake    chan int64
	count   *metrics.Counters
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	h := &harness{
		t:      t,
		db:     db,
		notify: &recorder{},
		wake:   make(chan int64, 8),
		count:  &metrics.Counters{},
	}
	cfg := config.HealthConfig{
		Interval:         time.Hour,
		Timeout:          2 * time.Second,
		FailureThreshold: 3,
		SuccessThreshold: 2,
	}
	h.checker = New(cfg, true, db, slog.New(slog.NewTextHandler(io.Discard, nil)), h.notify, h.wake, h.count)
	return h
}

func (h *harness) domain(host string, port int, enabled bool) int64 {
	h.t.Helper()
	id, err := h.db.CreateDomain(context.Background(), &store.Domain{
		Name: "example.test", PrimaryHost: host, PrimaryPort: port,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: enabled,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *harness) check(times int) {
	for i := 0; i < times; i++ {
		h.checker.checkAll(context.Background())
	}
}

func (h *harness) status(id int64) *store.PrimaryStatus {
	h.t.Helper()
	s, err := h.db.PrimaryStatusFor(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func (h *harness) timeline() []string {
	h.t.Helper()
	events, err := h.db.ListEvents(context.Background(), 100)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, e := range events {
		if e.Type == store.EventPrimaryUp || e.Type == store.EventPrimaryDown {
			out = append(out, e.Type)
		}
	}
	return out
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestPrimaryComesUpAfterTheSuccessThreshold(t *testing.T) {
	h := newHarness(t)
	p := startPrimary(t)
	id := h.domain(p.host, p.port, true)

	h.check(1)
	if h.status(id).IsUp {
		t.Fatal("primary marked up after one probe; the success threshold is 2")
	}
	if got := h.notify.events(); len(got) != 0 {
		t.Fatalf("notifications after one success = %v; want none", got)
	}

	h.check(1)
	if !h.status(id).IsUp {
		t.Fatal("primary still down after two successful probes")
	}
	if got := h.timeline(); len(got) != 1 || got[0] != store.EventPrimaryUp {
		t.Fatalf("timeline = %v; want one primary_up", got)
	}
	if got := h.notify.events(); len(got) != 1 || got[0] != store.EventPrimaryUp {
		t.Fatalf("notifications = %v; want one primary_up", got)
	}
	select {
	case woke := <-h.wake:
		if woke != id {
			t.Fatalf("woke the sender for domain %d; want %d", woke, id)
		}
	default:
		t.Fatal("the sender was not woken when the primary came up")
	}
	if total, failed := h.count.ProbesTotal.Load(), h.count.ProbesFailed.Load(); total != 2 || failed != 0 {
		t.Fatalf("probe counters = %d total, %d failed; want 2, 0", total, failed)
	}
}

func TestAPrimaryThatWasNeverReachableIsReportedOnce(t *testing.T) {
	h := newHarness(t)
	id := h.domain("127.0.0.1", closedPort(t), true)

	h.check(1)
	if got := h.timeline(); len(got) != 1 || got[0] != store.EventPrimaryDown {
		t.Fatalf("timeline after the first failed probe = %v; want one primary_down", got)
	}
	if got := h.notify.events(); len(got) != 1 || got[0] != store.EventPrimaryDown {
		t.Fatalf("notifications = %v; want one primary_down", got)
	}
	if s := h.status(id); s.IsUp || s.LastError == "" {
		t.Fatalf("status = up %v, last error %q; want down with the probe error", s.IsUp, s.LastError)
	}

	h.check(3)
	if got := h.timeline(); len(got) != 1 {
		t.Fatalf("timeline after more failures = %v; want still one event", got)
	}
	if failed := h.count.ProbesFailed.Load(); failed != 4 {
		t.Fatalf("failed probes = %d; want 4", failed)
	}
}

func TestPrimaryGoesDownOnlyAfterTheFailureThreshold(t *testing.T) {
	h := newHarness(t)
	p := startPrimary(t)
	id := h.domain(p.host, p.port, true)
	h.check(2)
	<-h.wake

	p.refuse.Store(true)
	h.check(2)
	if !h.status(id).IsUp {
		t.Fatal("primary marked down after two failures; the failure threshold is 3")
	}

	p.refuse.Store(false)
	h.check(1)
	p.refuse.Store(true)
	h.check(2)
	if !h.status(id).IsUp {
		t.Fatal("failures either side of a success were added together")
	}

	h.check(1)
	if h.status(id).IsUp {
		t.Fatal("primary still up after three consecutive failures")
	}
	want := []string{store.EventPrimaryDown, store.EventPrimaryUp}
	if got := h.timeline(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("timeline (newest first) = %v; want %v", got, want)
	}
	select {
	case <-h.wake:
		t.Fatal("the sender was woken for a primary going down")
	default:
	}
}

func TestRecoveryPullsTheQueueForward(t *testing.T) {
	h := newHarness(t)
	p := startPrimary(t)
	p.refuse.Store(true)
	id := h.domain(p.host, p.port, true)
	h.check(1)

	now := time.Now().UTC()
	err := h.db.Enqueue(context.Background(), &store.Message{
		ID: "waiting", DomainID: id, EnvelopeFrom: "a@sender.test",
		EnvelopeTo: []string{"b@example.test"}, SizeBytes: 10,
		ReceivedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		NextRetryAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	p.refuse.Store(false)
	h.check(2)

	m, err := h.db.GetMessage(context.Background(), "waiting")
	if err != nil {
		t.Fatal(err)
	}
	if m.NextRetryAt.After(time.Now().UTC()) {
		t.Fatalf("next retry still at %v after the primary recovered; want it due now", m.NextRetryAt)
	}
}

func TestDisabledDomainsAreNotProbed(t *testing.T) {
	h := newHarness(t)
	h.domain("127.0.0.1", closedPort(t), false)

	h.check(3)
	if total := h.count.ProbesTotal.Load(); total != 0 {
		t.Fatalf("probed a disabled domain %d times", total)
	}
	if got := h.timeline(); len(got) != 0 {
		t.Fatalf("timeline = %v; want nothing for a disabled domain", got)
	}
}

func TestASilentPrimaryIsBoundedByTheTimeout(t *testing.T) {
	p := startPrimary(t)
	p.silent.Store(true)

	d := &store.Domain{Name: "example.test", PrimaryHost: p.host, PrimaryPort: p.port, PrimaryTLS: "opportunistic"}
	start := time.Now()
	err := Probe(context.Background(), d, 300*time.Millisecond, true)
	if err == nil {
		t.Fatal("probe of a silent primary succeeded")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("probe took %v; want it bounded by the 300ms timeout", elapsed)
	}
}

func TestProbeSpeaksAsTheDomain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(c, "220 primary\r\n")
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		got <- strings.TrimSpace(line)
		fmt.Fprint(c, "250 primary\r\n")
		r.ReadString('\n')
		fmt.Fprint(c, "221 bye\r\n")
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	d := &store.Domain{Name: "example.test", PrimaryHost: "127.0.0.1", PrimaryPort: port, PrimaryTLS: "none"}
	if err := Probe(context.Background(), d, 2*time.Second, true); err != nil {
		t.Fatalf("Probe = %v", err)
	}
	if line := <-got; line != "EHLO xeronmx.example.test" {
		t.Fatalf("probe opened with %q; want EHLO xeronmx.example.test", line)
	}
}

func TestProbeRefusesAPrivatePrimaryUnlessAllowed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			fmt.Fprint(c, "220 primary\r\n")
			r := bufio.NewReader(c)
			r.ReadString('\n')
			fmt.Fprint(c, "250 primary\r\n")
			r.ReadString('\n')
			fmt.Fprint(c, "221 bye\r\n")
			c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	d := &store.Domain{Name: "example.test", PrimaryHost: "127.0.0.1", PrimaryPort: port, PrimaryTLS: "none"}

	if err := Probe(context.Background(), d, 2*time.Second, false); !errors.Is(err, smtpclient.ErrNonPublicAddress) {
		t.Fatalf("Probe(private, not allowed) = %v; want ErrNonPublicAddress", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the refused probe still opened %d connection(s)", n)
	}
	if err := Probe(context.Background(), d, 2*time.Second, true); err != nil {
		t.Fatalf("Probe(private, allowed) = %v", err)
	}
}
