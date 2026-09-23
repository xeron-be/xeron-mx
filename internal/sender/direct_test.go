package sender

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type fakeMX struct {
	mu      sync.Mutex
	mx      map[string][]*net.MX
	mxErr   map[string]error
	hosts   map[string]bool
	hostErr map[string]error
	asked   []string
}

func notFoundErr(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeMX) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "MX "+name)
	if err := f.mxErr[name]; err != nil {
		return nil, err
	}
	if recs, ok := f.mx[name]; ok {
		return recs, nil
	}
	return nil, notFoundErr(name)
}

func (f *fakeMX) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "A "+host)
	if err := f.hostErr[host]; err != nil {
		return nil, err
	}
	if f.hosts[host] {
		return []string{"192.0.2.1"}, nil
	}
	return nil, notFoundErr(host)
}

func (f *fakeMX) queried(q string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.asked, q)
}

func direct(h *harness, dns *fakeMX, servers map[string]int) {
	h.sender.resolver = dns
	h.sender.directAddr = func(host string) (string, int) {
		if port, ok := servers[host]; ok {
			return "127.0.0.1", port
		}
		return "127.0.0.1", closedPort(h.t)
	}
}

func directHarness(t *testing.T) *harness {
	t.Helper()
	p := startPrimary(t)
	return newHarness(t, p.host, p.port, 5*time.Second, func(c *config.Config) {
		c.Outbound.Enabled = true
		c.Outbound.Mode = "direct"
	})
}

func outbound(m *store.Message) {
	m.Direction = store.DirectionOutbound
	m.EnvelopeFrom = "boss@example.test"
}

func TestDirectDeliveryUsesTheMostPreferredMX(t *testing.T) {
	best, backup := startPrimary(t), startPrimary(t)
	h := directHarness(t)
	direct(h, &fakeMX{mx: map[string][]*net.MX{
		"dest.test": {{Host: "mx2.dest.test.", Pref: 20}, {Host: "mx1.dest.test.", Pref: 10}},
	}}, map[string]int{"mx1.dest.test": best.port, "mx2.dest.test": backup.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "carol@dest.test")

	h.pass()

	if got := h.message(id).Status; got != store.StatusDelivered {
		t.Fatalf("status = %s; want delivered", got)
	}
	if len(best.transactions()) != 1 || len(backup.transactions()) != 0 {
		t.Fatalf("pref 10 got %d, pref 20 got %d; want everything at pref 10",
			len(best.transactions()), len(backup.transactions()))
	}
}

func TestDirectDeliveryMovesToTheNextMXWhenOneIsDown(t *testing.T) {
	backup := startPrimary(t)
	h := directHarness(t)
	direct(h, &fakeMX{mx: map[string][]*net.MX{
		"dest.test": {{Host: "mx1.dest.test", Pref: 10}, {Host: "mx2.dest.test", Pref: 20}},
	}}, map[string]int{"mx1.dest.test": closedPort(t), "mx2.dest.test": backup.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "carol@dest.test")

	h.pass()

	if got := h.message(id).Status; got != store.StatusDelivered {
		t.Fatalf("status = %s (%s); want delivered through the second MX", got, h.message(id).LastError)
	}
	if txs := backup.transactions(); len(txs) != 1 || txs[0].body != testBody {
		t.Fatalf("second MX received %v", txs)
	}
}

func TestDirectDeliveryStopsAtAPermanentRefusal(t *testing.T) {
	first, second := startPrimary(t), startPrimary(t)
	first.setMailReply("550 5.7.1 sender blocked")
	h := directHarness(t)
	direct(h, &fakeMX{mx: map[string][]*net.MX{
		"dest.test": {{Host: "mx1.dest.test", Pref: 10}, {Host: "mx2.dest.test", Pref: 20}},
	}}, map[string]int{"mx1.dest.test": first.port, "mx2.dest.test": second.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "carol@dest.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusFailed || !strings.Contains(m.LastError, "550") {
		t.Fatalf("status = %s (%s); want failed on the 550", m.Status, m.LastError)
	}
	if second.connections() != 0 {
		t.Fatal("a permanent refusal was retried at the next MX")
	}
}

func TestDirectDeliveryFallsBackToTheAddressWithoutMX(t *testing.T) {
	host := startPrimary(t)
	h := directHarness(t)
	dns := &fakeMX{hosts: map[string]bool{"dest.test": true}}
	direct(h, dns, map[string]int{"dest.test": host.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "carol@dest.test")

	h.pass()

	if got := h.message(id).Status; got != store.StatusDelivered {
		t.Fatalf("status = %s (%s); want delivered to the domain's own address (RFC 5321 5.1)", got, h.message(id).LastError)
	}
	if len(host.transactions()) != 1 {
		t.Fatalf("the domain's host received %d messages", len(host.transactions()))
	}
}

func TestATemporaryDNSFailureDefersInsteadOfGuessing(t *testing.T) {
	host := startPrimary(t)
	h := directHarness(t)
	dns := &fakeMX{
		mxErr: map[string]error{"dest.test": &net.DNSError{Err: "server misbehaving", Name: "dest.test", IsTemporary: true}},
		hosts: map[string]bool{"dest.test": true},
	}
	direct(h, dns, map[string]int{"dest.test": host.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "carol@dest.test")

	h.pass()

	if got := h.message(id).Status; got != store.StatusQueued {
		t.Fatalf("status = %s; want queued for a retry", got)
	}
	if host.connections() != 0 || dns.queried("A dest.test") {
		t.Fatal("a failed MX lookup was taken as \"no MX\" and the mail went to the domain's address")
	}
}

func TestADomainThatCannotReceiveMailFailsAtOnce(t *testing.T) {
	for name, c := range map[string]struct {
		dns  *fakeMX
		want string
	}{
		"null MX":      {&fakeMX{mx: map[string][]*net.MX{"dest.test": {{Host: ".", Pref: 0}}}}, "556"},
		"no such name": {&fakeMX{}, "no MX and no address"},
	} {
		t.Run(name, func(t *testing.T) {
			h := directHarness(t)
			direct(h, c.dns, nil)
			id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "carol@dest.test")

			h.pass()

			m := h.message(id)
			if m.Status != store.StatusFailed || !strings.Contains(m.LastError, c.want) {
				t.Fatalf("status = %s (%s); want failed at once with %s, not retried for days", m.Status, m.LastError, c.want)
			}
		})
	}
}

func TestDirectDeliveryReachesEveryRecipientDomain(t *testing.T) {
	one, two := startPrimary(t), startPrimary(t)
	h := directHarness(t)
	direct(h, &fakeMX{mx: map[string][]*net.MX{
		"one.test": {{Host: "mx.one.test", Pref: 10}},
		"two.test": {{Host: "mx.two.test", Pref: 10}},
	}}, map[string]int{"mx.one.test": one.port, "mx.two.test": two.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "a@one.test", "b@two.test", "c@One.test")

	h.pass()

	if got := h.message(id).Status; got != store.StatusDelivered {
		t.Fatalf("status = %s (%s); want delivered to both domains", got, h.message(id).LastError)
	}
	if txs := one.transactions(); len(txs) != 1 || !slices.Equal(txs[0].rcpts, []string{"a@one.test", "c@One.test"}) {
		t.Fatalf("one.test received %v", txs)
	}
	if txs := two.transactions(); len(txs) != 1 || !slices.Equal(txs[0].rcpts, []string{"b@two.test"}) || txs[0].body != testBody {
		t.Fatalf("two.test received %v", txs)
	}
}

func TestOneUnreachableDomainDoesNotHoldBackTheOthers(t *testing.T) {
	one := startPrimary(t)
	h := directHarness(t)
	direct(h, &fakeMX{mx: map[string][]*net.MX{
		"one.test": {{Host: "mx.one.test", Pref: 10}},
		"two.test": {{Host: "mx.two.test", Pref: 10}},
	}}, map[string]int{"mx.one.test": one.port})
	id := h.enqueueMessage(testBody, 24*time.Hour, outbound, "a@one.test", "b@two.test")

	h.pass()

	m := h.message(id)
	if m.Status != store.StatusQueued || !slices.Equal(m.EnvelopeTo, []string{"b@two.test"}) {
		t.Fatalf("status = %s, recipients %v; want queued for b@two.test only", m.Status, m.EnvelopeTo)
	}
	if len(one.transactions()) != 1 {
		t.Fatal("one.test was held back by two.test being down")
	}
}

func TestADirectBounceKeepsTheNullSender(t *testing.T) {
	p := startPrimary(t)
	senderMX := startPrimary(t)
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarnessFor(t, p)
	direct(h, &fakeMX{mx: map[string][]*net.MX{
		"elsewhere.test": {{Host: "mx.elsewhere.test", Pref: 10}},
	}}, map[string]int{"mx.elsewhere.test": senderMX.port})
	h.enqueueMessage(testBody, 24*time.Hour, authenticated, "bob@example.test")

	h.pass()
	h.pass()

	txs := senderMX.transactions()
	if len(txs) != 1 {
		t.Fatalf("the sender's MX received %d messages; want the bounce", len(txs))
	}
	if txs[0].from != "" || !slices.Equal(txs[0].rcpts, []string{"sender@elsewhere.test"}) {
		t.Fatalf("bounce envelope %q -> %v; want <> to the sender (RFC 5321 4.5.5)", txs[0].from, txs[0].rcpts)
	}
	if !strings.Contains(txs[0].body, "Final-Recipient: rfc822; bob@example.test") {
		t.Fatal("the bounce does not report bob")
	}
}

func TestLookupMXOrdersAndReportsErrors(t *testing.T) {
	dns := &fakeMX{
		mx: map[string][]*net.MX{"a.test": {
			{Host: "c.a.test.", Pref: 30}, {Host: "a.a.test.", Pref: 10}, {Host: "b.a.test.", Pref: 10},
		}},
		mxErr: map[string]error{"broken.test": errors.New("i/o timeout")},
	}
	hosts, err := lookupMX(context.Background(), dns, "a.test")
	if err != nil || !slices.Equal(hosts, []string{"a.a.test", "b.a.test", "c.a.test"}) {
		t.Fatalf("lookupMX = %v, %v; want preference order, stable among equals", hosts, err)
	}
	if _, err := lookupMX(context.Background(), dns, "broken.test"); err == nil || strings.Contains(err.Error(), "5.1.2") {
		t.Fatalf("lookupMX on a broken resolver = %v; want a temporary error", err)
	}
}
