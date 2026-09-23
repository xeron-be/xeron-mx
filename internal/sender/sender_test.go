package sender

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/mailutil"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const testBody = "From: sender@elsewhere.test\r\n" +
	"To: alice@example.test\r\n" +
	"Subject: held while the primary was down\r\n" +
	"\r\n" +
	"First line.\r\n" +
	".A line that starts with a dot.\r\n" +
	"Last line.\r\n"

type transaction struct {
	from  string
	rcpts []string
	body  string
}

type primary struct {
	host string
	port int

	mu        sync.Mutex
	rcptReply map[string]string
	dataReply string
	mailReply string
	noNull    bool
	auth      string
	authed    bool
	dropAt    string
	silent    bool
	conns     int
	done      []transaction
}

func startPrimary(t *testing.T) *primary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &primary{host: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port, rcptReply: map[string]string{}}

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

func (p *primary) setRcptReply(rcpt, reply string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if reply == "" {
		delete(p.rcptReply, rcpt)
		return
	}
	p.rcptReply[rcpt] = reply
}

func (p *primary) setDataReply(reply string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dataReply = reply
}

func (p *primary) setMailReply(reply string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mailReply = reply
}

func (p *primary) setDropAt(stage string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dropAt = stage
}

func (p *primary) dropping(stage string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropAt == stage
}

func (p *primary) setSilent(silent bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.silent = silent
}

func (p *primary) transactions() []transaction {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.done)
}

func (p *primary) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns
}

func (p *primary) serve(c net.Conn, stop <-chan struct{}) {
	p.mu.Lock()
	p.conns++
	silent := p.silent
	p.mu.Unlock()
	if silent {
		<-stop
		return
	}

	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	reply := func(s string) { fmt.Fprint(c, s+"\r\n") }
	reply("220 primary ESMTP")

	var tx transaction
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			p.mu.Lock()
			offer := p.auth != ""
			p.mu.Unlock()
			if offer {
				reply("250-primary")
				reply("250 AUTH PLAIN")
			} else {
				reply("250 primary")
			}
		case "AUTH":
			mech, b64, _ := strings.Cut(arg, " ")
			raw, _ := base64.StdEncoding.DecodeString(b64)
			parts := strings.Split(string(raw), "\x00")
			p.mu.Lock()
			ok := strings.EqualFold(mech, "PLAIN") && len(parts) == 3 && parts[1]+":"+parts[2] == p.auth
			p.authed = p.authed || ok
			p.mu.Unlock()
			if ok {
				reply("235 2.7.0 authenticated")
			} else {
				reply("535 5.7.8 authentication credentials invalid")
			}
		case "MAIL":
			p.mu.Lock()
			resp := p.mailReply
			if p.noNull && address(arg) == "" {
				resp = "501 Invalid MAIL FROM address provided"
			}
			p.mu.Unlock()
			if resp != "" {
				reply(resp)
				continue
			}
			tx = transaction{from: address(arg)}
			reply("250 2.1.0 ok")
		case "RCPT":
			if p.dropping("rcpt") {
				return
			}
			rcpt := address(arg)
			p.mu.Lock()
			resp, scripted := p.rcptReply[rcpt]
			p.mu.Unlock()
			if scripted {
				reply(resp)
				continue
			}
			tx.rcpts = append(tx.rcpts, rcpt)
			reply("250 2.1.5 ok")
		case "DATA":
			if len(tx.rcpts) == 0 {
				reply("554 5.5.1 no valid recipients")
				continue
			}
			reply("354 go ahead")
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				if p.dropping("data") {
					return
				}
				body.WriteString(strings.TrimPrefix(l, "."))
			}
			tx.body = body.String()
			p.mu.Lock()
			resp := p.dataReply
			if resp == "" {
				resp = "250 2.0.0 queued"
			}
			if strings.HasPrefix(resp, "250") {
				p.done = append(p.done, tx)
			}
			p.mu.Unlock()
			reply(resp)
			if p.dropping("after-data") {
				return
			}
		case "RSET":
			tx = transaction{}
			reply("250 2.0.0 ok")
		case "QUIT":
			reply("221 2.0.0 bye")
			return
		default:
			reply("502 5.5.2 not implemented")
		}
	}
}

func address(arg string) string {
	start, end := strings.Index(arg, "<"), strings.Index(arg, ">")
	if start < 0 || end < start {
		return arg
	}
	return arg[start+1 : end]
}

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) Notify(event string, _ map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recorder) seen(event string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.events, event)
}

type harness struct {
	t        *testing.T
	db       *store.DB
	blobs    *blob.Store
	sender   *Sender
	notify   *recorder
	count    *metrics.Counters
	domainID int64
}

func newHarness(t *testing.T, host string, port int, deliveryTimeout time.Duration, opts ...func(*config.Config)) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	db, err := store.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}

	id, err := db.CreateDomain(ctx, &store.Domain{
		Name: "example.test", PrimaryHost: host, PrimaryPort: port,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.RecordProbe(ctx, id, true, "", 1, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Queue.Workers = 2
	cfg.Queue.DeliveryTimeout = deliveryTimeout
	for _, opt := range opts {
		opt(&cfg)
	}
	h := &harness{t: t, db: db, blobs: blobs, notify: &recorder{}, count: &metrics.Counters{}, domainID: id}
	h.sender = New(cfg.Queue, db, blobs, slog.New(slog.NewTextHandler(io.Discard, nil)),
		h.notify, nil, h.count, cfg.Outbound, "mx2.example.test")
	return h
}

func newHarnessFor(t *testing.T, p *primary) *harness {
	return newHarness(t, p.host, p.port, 5*time.Second)
}

func (h *harness) enqueue(expires time.Duration, rcpts ...string) string {
	h.t.Helper()
	return h.enqueueBody(testBody, expires, rcpts...)
}

func (h *harness) enqueueBody(body string, expires time.Duration, rcpts ...string) string {
	h.t.Helper()
	return h.enqueueMessage(body, expires, nil, rcpts...)
}

func (h *harness) enqueueMessage(body string, expires time.Duration, mutate func(*store.Message), rcpts ...string) string {
	h.t.Helper()
	id, err := mailutil.NewID()
	if err != nil {
		h.t.Fatal(err)
	}
	n, err := h.blobs.Put(id, strings.NewReader(body), 1<<20)
	if err != nil {
		h.t.Fatal(err)
	}
	now := time.Now().UTC()
	m := &store.Message{
		ID: id, DomainID: h.domainID, EnvelopeFrom: "sender@elsewhere.test",
		EnvelopeTo: rcpts, SizeBytes: n, ReceivedAt: now,
		ExpiresAt: now.Add(expires), NextRetryAt: now,
	}
	if mutate != nil {
		mutate(m)
	}
	if err := h.db.Enqueue(context.Background(), m); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *harness) pass() {
	h.sender.pass(context.Background())
}

func (h *harness) message(id string) *store.Message {
	h.t.Helper()
	m, err := h.db.GetMessage(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return m
}

func (h *harness) bodyKept(id string) bool {
	r, err := h.blobs.Get(id)
	if err != nil {
		return false
	}
	r.Close()
	return true
}

func (h *harness) events(typ string) []*store.Event {
	h.t.Helper()
	all, err := h.db.ListEvents(context.Background(), 100)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []*store.Event
	for _, e := range all {
		if e.Type == typ {
			out = append(out, e)
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

func TestDeliveredByteForByteThenRemoved(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	txs := p.transactions()
	if len(txs) != 1 {
		t.Fatalf("primary received %d transactions; want 1", len(txs))
	}
	if txs[0].from != "sender@elsewhere.test" || !slices.Equal(txs[0].rcpts, []string{"alice@example.test"}) {
		t.Fatalf("envelope = %q -> %q; want the original envelope", txs[0].from, txs[0].rcpts)
	}
	if txs[0].body != testBody {
		t.Fatalf("primary received\n%q\nwant the spooled bytes\n%q", txs[0].body, testBody)
	}
	if m := h.message(id); m.Status != store.StatusDelivered || m.DeliveredAt == nil {
		t.Fatalf("status = %s; want delivered", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the encrypted body is still on disk after delivery")
	}
	if len(h.events(store.EventMailDelivered)) != 1 || h.count.MessagesDelivered.Load() != 1 {
		t.Fatal("delivery not recorded on the timeline and in the counters")
	}
}

func TestTemporaryRejectionKeepsTheMessage(t *testing.T) {
	p := startPrimary(t)
	p.setDataReply("451 4.3.0 try again later")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusQueued || m.Attempts != 1 {
		t.Fatalf("status %s after %d attempts; want queued after 1", m.Status, m.Attempts)
	}
	if !m.NextRetryAt.After(time.Now().UTC()) {
		t.Fatal("next retry is not in the future: the backoff was not applied")
	}
	if !strings.Contains(m.LastError, "451") {
		t.Fatalf("last error = %q; want the primary's answer", m.LastError)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted after a temporary failure")
	}
}

func TestPermanentRejectionFailsTheMessage(t *testing.T) {
	p := startPrimary(t)
	p.setDataReply("554 5.7.1 message refused")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	if m := h.message(id); m.Status != store.StatusFailed {
		t.Fatalf("status = %s; want failed", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the body of a permanently rejected message is still on disk")
	}
	if !h.notify.seen(store.EventMailFailed) {
		t.Fatal("no mail_failed notification")
	}
}

func TestOneRejectedRecipientDoesNotCostTheOthers(t *testing.T) {
	p := startPrimary(t)
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test", "bob@example.test", "carol@example.test")

	h.pass()

	txs := p.transactions()
	if len(txs) != 1 || !slices.Equal(txs[0].rcpts, []string{"alice@example.test", "carol@example.test"}) {
		t.Fatalf("primary accepted %v; want alice and carol delivered", txs)
	}
	if m := h.message(id); m.Status != store.StatusDelivered {
		t.Fatalf("status = %s; want delivered", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the body is still on disk although every recipient is settled")
	}
	failed := h.events(store.EventMailFailed)
	if len(failed) != 1 || !strings.Contains(fmt.Sprint(failed[0].Data["to"]), "bob@example.test") {
		t.Fatalf("mail_failed events = %v; want one naming bob", failed)
	}
}

func TestADeferredRecipientIsRetriedAlone(t *testing.T) {
	p := startPrimary(t)
	p.setRcptReply("bob@example.test", "450 4.2.1 mailbox busy")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test", "bob@example.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusQueued || !slices.Equal(m.EnvelopeTo, []string{"bob@example.test"}) {
		t.Fatalf("after the first attempt: status %s, recipients %v; want queued for bob only", m.Status, m.EnvelopeTo)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted while bob is still waiting")
	}

	p.setRcptReply("bob@example.test", "")
	if err := h.db.RetryNow(context.Background(), id, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h.pass()

	txs := p.transactions()
	if len(txs) != 2 ||
		!slices.Equal(txs[0].rcpts, []string{"alice@example.test"}) ||
		!slices.Equal(txs[1].rcpts, []string{"bob@example.test"}) {
		t.Fatalf("transactions = %v; want alice first, then bob alone", txs)
	}
	if m := h.message(id); m.Status != store.StatusDelivered {
		t.Fatalf("status = %s; want delivered once bob accepted", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the body is still on disk after the last recipient accepted")
	}
}

func TestEveryRecipientRejected(t *testing.T) {
	p := startPrimary(t)
	p.setRcptReply("alice@example.test", "550 5.1.1 no such user")
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test", "bob@example.test")

	h.pass()

	if m := h.message(id); m.Status != store.StatusFailed {
		t.Fatalf("status = %s; want failed", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the body is still on disk although no recipient exists")
	}
	if len(p.transactions()) != 0 {
		t.Fatal("DATA was sent with no accepted recipient")
	}
}

func TestEveryRecipientDeferred(t *testing.T) {
	p := startPrimary(t)
	p.setRcptReply("alice@example.test", "452 4.2.2 over quota")
	p.setRcptReply("bob@example.test", "451 4.3.0 try later")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test", "bob@example.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusQueued || len(m.EnvelopeTo) != 2 || m.Attempts != 1 {
		t.Fatalf("status %s, recipients %v, attempts %d; want queued for both after 1 attempt",
			m.Status, m.EnvelopeTo, m.Attempts)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted after temporary failures only")
	}
}

func TestUnreachablePrimaryDefers(t *testing.T) {
	h := newHarness(t, "127.0.0.1", closedPort(t), 5*time.Second)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	if m := h.message(id); m.Status != store.StatusQueued || m.Attempts != 1 {
		t.Fatalf("status %s after %d attempts; want queued after 1", m.Status, m.Attempts)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted because the primary could not be reached")
	}
}

func TestAStalledPrimaryIsBoundedByTheDeliveryTimeout(t *testing.T) {
	p := startPrimary(t)
	p.setSilent(true)
	h := newHarness(t, p.host, p.port, 300*time.Millisecond)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	start := time.Now()
	h.pass()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("delivery pass took %v; want it bounded by the 300ms delivery timeout", elapsed)
	}
	if m := h.message(id); m.Status != store.StatusQueued || !h.bodyKept(id) {
		t.Fatalf("status %s; want queued with the body kept", m.Status)
	}
}

func TestNothingIsAttemptedWhileThePrimaryIsDown(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	if _, _, err := h.db.RecordProbe(context.Background(), h.domainID, false, "down", 1, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	if n := p.connections(); n != 0 {
		t.Fatalf("connected to a primary marked down %d times", n)
	}
	if m := h.message(id); m.Status != store.StatusQueued || m.Attempts != 0 {
		t.Fatalf("status %s after %d attempts; want untouched", m.Status, m.Attempts)
	}
}

func TestExpiredMessagesAreDroppedAndReported(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	id := h.enqueue(-time.Minute, "alice@example.test")

	h.sender.maintain(context.Background())

	if m := h.message(id); m.Status != store.StatusExpired {
		t.Fatalf("status = %s; want expired", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the body of an expired message is still on disk")
	}
	if !h.notify.seen(store.EventMailExpired) || len(h.events(store.EventMailExpired)) != 1 {
		t.Fatal("expiry not reported")
	}
}

func TestStartupRequeuesClaimsLeftByACrash(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")
	claimed, err := h.db.ClaimBatch(context.Background(), "a-previous-run", 10, time.Now().UTC())
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimBatch = %d, %v", len(claimed), err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.sender.Run(ctx)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if m := h.message(id); m.Status != store.StatusQueued {
		t.Fatalf("status = %s; want the crashed claim back in the queue", m.Status)
	}
}

func TestAConnectionCutDuringDataKeepsTheMessage(t *testing.T) {
	p := startPrimary(t)
	p.setDropAt("data")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	if m := h.message(id); m.Status != store.StatusQueued || m.Attempts != 1 {
		t.Fatalf("status %s after %d attempts; want queued after 1", m.Status, m.Attempts)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted although the primary never confirmed the message")
	}
	if len(p.transactions()) != 0 {
		t.Fatal("the primary recorded a message it never confirmed")
	}
}

func TestAConnectionCutAfterTheFinalDotIsStillADelivery(t *testing.T) {
	p := startPrimary(t)
	p.setDropAt("after-data")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	if m := h.message(id); m.Status != store.StatusDelivered {
		t.Fatalf("status = %s; want delivered: the primary answered 250 to the final dot", m.Status)
	}
	if h.bodyKept(id) {
		t.Fatal("the body is still on disk after the primary accepted the message")
	}
	if n := len(p.transactions()); n != 1 {
		t.Fatalf("primary holds %d copies; want 1", n)
	}
}

func TestAConnectionCutDuringRcptKeepsTheMessage(t *testing.T) {
	p := startPrimary(t)
	p.setDropAt("rcpt")
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test", "bob@example.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusQueued || len(m.EnvelopeTo) != 2 {
		t.Fatalf("status %s, recipients %v; want queued for both", m.Status, m.EnvelopeTo)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted after the connection dropped")
	}
}

func TestMailFromRejection(t *testing.T) {
	cases := []struct {
		reply  string
		status store.Status
		kept   bool
	}{
		{"451 4.7.1 greylisted, try again later", store.StatusQueued, true},
		{"550 5.7.1 sender blocked", store.StatusFailed, false},
	}
	for _, c := range cases {
		t.Run(c.reply[:3], func(t *testing.T) {
			p := startPrimary(t)
			p.setMailReply(c.reply)
			h := newHarnessFor(t, p)
			id := h.enqueue(24*time.Hour, "alice@example.test")

			h.pass()

			if m := h.message(id); m.Status != c.status {
				t.Fatalf("status = %s; want %s", m.Status, c.status)
			}
			if h.bodyKept(id) != c.kept {
				t.Fatalf("body kept = %v; want %v", h.bodyKept(id), c.kept)
			}
		})
	}
}

func TestAnUnreadableBodyFailsLoudly(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	id := h.enqueue(24*time.Hour, "alice@example.test")
	if err := h.blobs.Delete(id); err != nil {
		t.Fatal(err)
	}

	h.pass()

	if m := h.message(id); m.Status != store.StatusFailed {
		t.Fatalf("status = %s; want failed", m.Status)
	}
	if !h.notify.seen(store.EventMailFailed) || len(h.events(store.EventMailFailed)) != 1 {
		t.Fatal("a lost body was not reported")
	}
	if n := p.connections(); n != 0 {
		t.Fatalf("connected to the primary %d times with nothing to send", n)
	}
}

func TestARecoveredPrimaryIsDrainedAtOnce(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	wake := make(chan int64, 1)
	h.sender.wake = wake
	id := h.enqueue(24*time.Hour, "alice@example.test")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.sender.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	wake <- h.domainID
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.message(id).Status == store.StatusDelivered {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("not delivered within 3s of the wake-up; the next tick is 15s away")
}

func TestTheARCSealClaimsOnlyWhatWasChecked(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	storeKey(t, h.db, h.blobs, h.domainID, true)
	h.enqueue(24*time.Hour, "alice@example.test")

	h.pass()

	txs := p.transactions()
	if len(txs) != 1 {
		t.Fatalf("primary received %d transactions; want 1", len(txs))
	}
	body := txs[0].body
	if !strings.HasPrefix(body, "ARC-Seal: i=1;") {
		t.Fatalf("the message was not sealed: %q", body[:min(len(body), 200)])
	}
	if !strings.Contains(body, "ARC-Authentication-Results: i=1; mx2.example.test; none\r\n") {
		t.Fatalf("the seal does not record an honest no-result: %q", body)
	}
	if strings.Contains(body, "=pass") {
		t.Fatalf("the seal vouches for a check that never ran: %q", body)
	}
	if !strings.HasSuffix(body, testBody) {
		t.Fatal("the original message is not intact under the seal")
	}
}

func TestAMessageAlreadyInAnARCChainIsForwardedUnsealed(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	storeKey(t, h.db, h.blobs, h.domainID, true)
	chained := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=list.test; s=s1; b=abc\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=list.test; s=s1; b=abc\r\n" +
		"ARC-Authentication-Results: i=1; list.test; spf=pass\r\n" +
		testBody
	id := h.enqueueBody(chained, 24*time.Hour, "alice@example.test")

	h.pass()

	txs := p.transactions()
	if len(txs) != 1 || txs[0].body != chained {
		t.Fatalf("primary received %v; want the message byte for byte, without a seal over a chain nobody validated", txs)
	}
	if m := h.message(id); m.Status != store.StatusDelivered {
		t.Fatalf("status = %s; want delivered", m.Status)
	}
}

func TestAValidatedARCChainIsExtended(t *testing.T) {
	chained := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=list.test; s=s1; b=abc\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=list.test; s=s1; b=abc\r\n" +
		"ARC-Authentication-Results: i=1; list.test; spf=pass\r\n" +
		testBody
	for _, cv := range []string{"pass", "fail"} {
		t.Run(cv, func(t *testing.T) {
			p := startPrimary(t)
			h := newHarnessFor(t, p)
			storeKey(t, h.db, h.blobs, h.domainID, true)
			h.enqueueMessage(chained, 24*time.Hour, func(m *store.Message) {
				m.AuthResults = "spf=fail smtp.mailfrom=list.test; dkim=none; arc=" + cv
			}, "alice@example.test")

			h.pass()

			txs := p.transactions()
			if len(txs) != 1 {
				t.Fatalf("primary received %d transactions; want 1", len(txs))
			}
			body := txs[0].body
			if !strings.HasPrefix(body, "ARC-Seal: i=2; a=rsa-sha256; cv="+cv+";") {
				t.Fatalf("the chain was not extended with cv=%s: %q", cv, body[:min(len(body), 200)])
			}
			if !strings.Contains(body, "ARC-Authentication-Results: i=2; mx2.example.test; spf=fail smtp.mailfrom=list.test; dkim=none; arc="+cv+"\r\n") {
				t.Fatalf("the new set does not carry the intake results: %q", body)
			}
			if !strings.HasSuffix(body, chained) {
				t.Fatal("the existing chain and message are not intact under the new set")
			}
		})
	}
}

func TestTheARCSealCarriesTheResultsCheckedAtIntake(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	storeKey(t, h.db, h.blobs, h.domainID, true)
	id, err := mailutil.NewID()
	if err != nil {
		t.Fatal(err)
	}
	n, err := h.blobs.Put(id, strings.NewReader(testBody), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = h.db.Enqueue(context.Background(), &store.Message{
		ID: id, DomainID: h.domainID, EnvelopeFrom: "sender@elsewhere.test",
		EnvelopeTo: []string{"alice@example.test"}, SizeBytes: n, ReceivedAt: now,
		ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
		AuthResults:         "spf=pass smtp.mailfrom=elsewhere.test; dkim=none",
		SenderAuthenticated: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	h.pass()

	txs := p.transactions()
	if len(txs) != 1 {
		t.Fatalf("primary received %d transactions; want 1", len(txs))
	}
	want := "ARC-Authentication-Results: i=1; mx2.example.test; spf=pass smtp.mailfrom=elsewhere.test; dkim=none\r\n"
	if !strings.Contains(txs[0].body, want) {
		t.Fatalf("the seal does not carry the intake results: %q", txs[0].body)
	}
}

func viaRelay(relay *primary) func(*config.Config) {
	return func(c *config.Config) {
		c.Outbound.Enabled = true
		c.Outbound.Mode = "relay"
		c.Outbound.RelayHost = relay.host
		c.Outbound.RelayPort = relay.port
		c.Outbound.RelayTLS = "none"
	}
}

func authenticated(m *store.Message) { m.SenderAuthenticated = true }

func (h *harness) outbound() []*store.Message {
	h.t.Helper()
	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{Direction: store.DirectionOutbound})
	if err != nil {
		h.t.Fatal(err)
	}
	return msgs
}

func TestAnAuthenticatedSenderIsToldAboutARejectedRecipient(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay))
	id := h.enqueueMessage(testBody, 24*time.Hour, authenticated, "alice@example.test", "bob@example.test")

	h.pass()

	if txs := p.transactions(); len(txs) != 1 || !slices.Equal(txs[0].rcpts, []string{"alice@example.test"}) {
		t.Fatalf("primary received %v; want alice delivered", txs)
	}
	bounces := relay.transactions()
	if len(bounces) != 1 {
		t.Fatalf("the relay carried %d messages; want one bounce", len(bounces))
	}
	b := bounces[0]
	if b.from != "" || !slices.Equal(b.rcpts, []string{"sender@elsewhere.test"}) {
		t.Fatalf("bounce envelope %q -> %v; want the null sender to the original sender", b.from, b.rcpts)
	}
	for _, want := range []string{
		"Final-Recipient: rfc822; bob@example.test",
		"Status: 5.1.1",
		"X-XeronMX-Queue-ID: " + id,
		"Subject: held while the primary was down",
	} {
		if !strings.Contains(b.body, want) {
			t.Errorf("bounce lacks %q", want)
		}
	}
	if strings.Contains(b.body, "Final-Recipient: rfc822; alice@example.test") {
		t.Error("the bounce reports a recipient who received the message")
	}
}

func TestABounceGoesOutThroughARelayThatRefusesTheNullSender(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	relay.mu.Lock()
	relay.noNull = true
	relay.mu.Unlock()
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay))
	h.enqueueMessage(testBody, 24*time.Hour, authenticated, "bob@example.test")

	h.pass()
	h.pass()

	bounces := relay.transactions()
	if len(bounces) != 1 {
		t.Fatalf("the relay carried %d messages; want the bounce, sent again from a real address", len(bounces))
	}
	if b := bounces[0]; b.from != "MAILER-DAEMON@mx2.example.test" || !slices.Equal(b.rcpts, []string{"sender@elsewhere.test"}) {
		t.Fatalf("bounce envelope %q -> %v; want MAILER-DAEMON@mx2.example.test to the original sender", b.from, b.rcpts)
	}
	for _, m := range h.outbound() {
		if m.Status != store.StatusDelivered {
			t.Fatalf("bounce status = %s (%s); want delivered", m.Status, m.LastError)
		}
	}
}

func authedRelay(relay *primary, user, pass string) func(*config.Config) {
	return func(c *config.Config) {
		viaRelay(relay)(c)
		c.Outbound.RelayUsername = user
		c.Outbound.RelayPassword = pass
	}
}

func TestSubmittedMailAuthenticatesToTheRelay(t *testing.T) {
	relay := startPrimary(t)
	relay.mu.Lock()
	relay.auth = "smtp-user:right-password"
	relay.mu.Unlock()
	p := startPrimary(t)
	h := newHarness(t, p.host, p.port, 5*time.Second, authedRelay(relay, "smtp-user", "right-password"))
	id := h.enqueueMessage(testBody, 24*time.Hour, func(m *store.Message) {
		m.Direction = store.DirectionOutbound
		m.EnvelopeFrom = "boss@example.test"
	}, "someone@elsewhere.test")

	h.pass()

	relay.mu.Lock()
	authed := relay.authed
	relay.mu.Unlock()
	if !authed || h.message(id).Status != store.StatusDelivered || len(relay.transactions()) != 1 {
		t.Fatalf("authenticated %v, status %s, relayed %d; want an authenticated delivery",
			authed, h.message(id).Status, len(relay.transactions()))
	}
}

func TestWrongRelayCredentialsHoldTheMailInsteadOfFailingIt(t *testing.T) {
	relay := startPrimary(t)
	relay.mu.Lock()
	relay.auth = "smtp-user:right-password"
	relay.mu.Unlock()
	p := startPrimary(t)
	h := newHarness(t, p.host, p.port, 5*time.Second, authedRelay(relay, "smtp-user", "a typo"))
	id := h.enqueueMessage(testBody, 24*time.Hour, func(m *store.Message) {
		m.Direction = store.DirectionOutbound
		m.EnvelopeFrom = "boss@example.test"
	}, "someone@elsewhere.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusQueued || !strings.Contains(m.LastError, "credentials") {
		t.Fatalf("status = %s (%s); want queued: a typo in the relay password must not bounce every outgoing message", m.Status, m.LastError)
	}
	if !h.bodyKept(id) {
		t.Fatal("the body was deleted")
	}
	if len(relay.transactions()) != 0 {
		t.Fatal("the relay accepted mail without authentication")
	}
}

func TestOnlyABounceFallsBackFromTheNullSender(t *testing.T) {
	if !refusedNullSender(fmt.Errorf("%w: %w", errMailFrom, &smtp.SMTPError{Code: 501})) {
		t.Fatal("a 501 at MAIL FROM is a refused null sender")
	}
	for _, err := range []error{
		fmt.Errorf("%w: %w", errMailFrom, &smtp.SMTPError{Code: 451}),
		fmt.Errorf("RCPT TO x: %w", &smtp.SMTPError{Code: 550}),
		errors.New("connection reset"),
		nil,
	} {
		if refusedNullSender(err) {
			t.Fatalf("refusedNullSender(%v) = true", err)
		}
	}
}

func TestAnUnauthenticatedSenderGetsNoBounce(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay))
	h.enqueue(24*time.Hour, "bob@example.test")

	h.pass()

	if n := len(h.outbound()); n != 0 {
		t.Fatalf("%d bounces queued for a sender nobody authenticated", n)
	}
	if n := relay.connections(); n != 0 {
		t.Fatalf("the relay was contacted %d times", n)
	}
}

func TestAWholeMessageRefusalIsBounced(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	p.setDataReply("554 5.7.1 message refused")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay))
	h.enqueueMessage(testBody, 24*time.Hour, authenticated, "alice@example.test", "bob@example.test")

	h.pass()

	bounces := relay.transactions()
	if len(bounces) != 1 {
		t.Fatalf("the relay carried %d messages; want one bounce", len(bounces))
	}
	for _, rcpt := range []string{"alice@example.test", "bob@example.test"} {
		if !strings.Contains(bounces[0].body, "Final-Recipient: rfc822; "+rcpt+"\r\nAction: failed\r\nStatus: 5.7.1") {
			t.Errorf("bounce does not report %s as refused with 5.7.1", rcpt)
		}
	}
}

func TestExpiryIsBouncedToAnAuthenticatedSender(t *testing.T) {
	p := startPrimary(t)
	h := newHarnessFor(t, p)
	id := h.enqueueMessage(testBody, -time.Minute, authenticated, "alice@example.test")

	h.sender.maintain(context.Background())

	bounces := h.outbound()
	if len(bounces) != 1 {
		t.Fatalf("%d bounces queued; want one for the expired message", len(bounces))
	}
	b := bounces[0]
	if b.EnvelopeFrom != "" || !slices.Equal(b.EnvelopeTo, []string{"sender@elsewhere.test"}) {
		t.Fatalf("bounce envelope %q -> %v", b.EnvelopeFrom, b.EnvelopeTo)
	}
	r, err := h.blobs.Get(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r)
	r.Close()
	if !strings.Contains(string(body), "Status: 4.4.7") || !strings.Contains(string(body), "Subject: held while the primary was down") {
		t.Fatalf("the expiry bounce does not say what happened:\n%s", body)
	}
	if h.bodyKept(id) {
		t.Fatal("the expired body is still on disk")
	}
}

func TestABounceIsNeverBounced(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	relay.setRcptReply("sender@elsewhere.test", "550 5.1.1 no such user")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay))
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h.enqueueMessage(testBody, 24*time.Hour, authenticated, "bob@example.test")

	h.pass()

	msgs := h.outbound()
	if len(msgs) != 1 {
		t.Fatalf("%d outbound messages; want only the first bounce, refused and not bounced again", len(msgs))
	}
	if msgs[0].Status != store.StatusFailed {
		t.Fatalf("the refused bounce is %s; want failed", msgs[0].Status)
	}
}

func TestBouncesCanBeSwitchedOff(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay), func(c *config.Config) {
		c.Queue.Bounces = config.BouncesOff
	})
	h.enqueueMessage(testBody, 24*time.Hour, authenticated, "bob@example.test")

	h.pass()

	if n := len(h.outbound()); n != 0 {
		t.Fatalf("%d bounces queued with bounces off", n)
	}
}
