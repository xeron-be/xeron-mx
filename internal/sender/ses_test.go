package sender

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func viaSES(relay *primary) func(*config.Config) {
	return func(c *config.Config) {
		viaRelay(relay)(c)
		c.Outbound.SES.ConfigurationSet = "xeronmx"
	}
}

func outboundFrom(from string) func(*store.Message) {
	return func(m *store.Message) {
		m.Direction = store.DirectionOutbound
		m.EnvelopeFrom = from
	}
}

func TestMailThroughSESCarriesTheConfigurationSetAndCounts(t *testing.T) {
	relay := startPrimary(t)
	p := startPrimary(t)
	h := newHarness(t, p.host, p.port, 5*time.Second, viaSES(relay))
	h.enqueueMessage(testBody, 24*time.Hour, outboundFrom("boss@example.test"), "a@far.test", "b@far.test")

	h.pass()

	txs := relay.transactions()
	if len(txs) != 1 || !strings.HasPrefix(txs[0].body, "X-SES-CONFIGURATION-SET: xeronmx\r\n") {
		t.Fatalf("relayed %d messages; want one starting with the configuration set header", len(txs))
	}
	w, err := h.db.SendingStats(context.Background(), h.domainID, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if w.Sent != 2 {
		t.Fatalf("sent = %d; want both recipients counted", w.Sent)
	}
}

func TestWithoutAConfigurationSetNothingIsAddedOrCounted(t *testing.T) {
	relay := startPrimary(t)
	p := startPrimary(t)
	h := newHarness(t, p.host, p.port, 5*time.Second, viaRelay(relay))
	h.enqueueMessage(testBody, 24*time.Hour, outboundFrom("boss@example.test"), "a@far.test")

	h.pass()

	txs := relay.transactions()
	if len(txs) != 1 || strings.Contains(txs[0].body, "X-SES-CONFIGURATION-SET") {
		t.Fatalf("relayed %v", txs)
	}
	if w, _ := h.db.SendingStats(context.Background(), h.domainID, time.Now().Add(-time.Hour)); w.Sent != 0 {
		t.Fatalf("sent = %d with SES events off", w.Sent)
	}
}

func TestBouncesXeronMXWritesAreNotCountedAsTheDomainsMail(t *testing.T) {
	p := startPrimary(t)
	relay := startPrimary(t)
	p.setRcptReply("bob@example.test", "550 5.1.1 no such user")
	h := newHarness(t, p.host, p.port, 5*time.Second, viaSES(relay))
	h.enqueueMessage(testBody, 24*time.Hour, authenticated, "bob@example.test")

	h.pass()
	h.pass()

	if len(relay.transactions()) != 1 {
		t.Fatalf("relayed %d; want the bounce", len(relay.transactions()))
	}
	if w, _ := h.db.SendingStats(context.Background(), h.domainID, time.Now().Add(-time.Hour)); w.Sent != 0 {
		t.Fatalf("sent = %d; a bounce from the null sender was counted", w.Sent)
	}
}
