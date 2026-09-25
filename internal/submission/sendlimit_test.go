package submission

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

func (h *harness) limit(t *testing.T, domainID int64, n int64) {
	t.Helper()
	d, err := h.db.DomainByID(context.Background(), domainID)
	if err != nil {
		t.Fatal(err)
	}
	d.MonthlySendLimit = &n
	if err := h.db.UpdateDomain(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) send(t *testing.T, from string, to ...string) error {
	t.Helper()
	c := h.authed(t, "mailserver")
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	io.WriteString(w, "Subject: quota\r\n\r\nhello")
	return w.Close()
}

func TestTheMonthlyLimitCountsRecipients(t *testing.T) {
	h := newHarness(t)
	id := h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)
	h.limit(t, id, 3)

	if err := h.send(t, "a@example.com", "one@far.example", "two@far.example"); err != nil {
		t.Fatalf("two recipients under a limit of three: %v", err)
	}
	err := h.send(t, "a@example.com", "three@far.example", "four@far.example")
	if err == nil || !strings.Contains(err.Error(), "monthly sending limit") {
		t.Fatalf("a fourth recipient was not refused: %v", err)
	}
	if err := h.send(t, "a@example.com", "three@far.example"); err != nil {
		t.Fatalf("the third recipient was refused: %v", err)
	}
	if err := h.send(t, "b@example.com", "five@far.example"); err == nil {
		t.Fatal("sent past the limit")
	}

	sent, err := h.db.SentThisMonth(context.Background(), id, time.Now())
	if err != nil || sent != 3 {
		t.Fatalf("usage = %d, %v; want 3", sent, err)
	}
	msgs, _ := h.db.ListMessages(context.Background(), store.ListFilter{})
	if len(msgs) != 2 {
		t.Fatalf("queued %d messages; want the two that fit", len(msgs))
	}

	events, _ := h.db.ListEvents(context.Background(), 50)
	reached := 0
	for _, e := range events {
		if e.Type == store.EventSendLimitReached {
			reached++
		}
	}
	if reached != 1 {
		t.Fatalf("send_limit_reached recorded %d times; want once", reached)
	}
}

func TestTheLimitIsPerDomainAndOptional(t *testing.T) {
	h := newHarness(t)
	limited := h.addDomain(t, "small.example")
	h.addDomain(t, "free.example")
	h.addUser(t, "mailserver", nil)
	h.limit(t, limited, 1)

	if err := h.send(t, "a@small.example", "x@far.example"); err != nil {
		t.Fatal(err)
	}
	if err := h.send(t, "a@small.example", "y@far.example"); err == nil {
		t.Fatal("the limited domain sent past its limit")
	}
	for i := 0; i < 5; i++ {
		if err := h.send(t, "a@free.example", "z@far.example"); err != nil {
			t.Fatalf("a domain without a limit was refused: %v", err)
		}
	}
}

func TestLastMonthDoesNotCount(t *testing.T) {
	h := newHarness(t)
	id := h.addDomain(t, "example.com")
	limit := int64(2)
	ctx := context.Background()
	lastMonth := time.Now().UTC().AddDate(0, -1, 0)

	if ok, _, err := h.db.ReserveSends(ctx, id, 2, &limit, lastMonth); !ok || err != nil {
		t.Fatalf("reserve last month: %v %v", ok, err)
	}
	if ok, before, err := h.db.ReserveSends(ctx, id, 2, &limit, time.Now()); !ok || before != 0 || err != nil {
		t.Fatalf("this month started at %d (%v, %v); want a fresh count", before, ok, err)
	}
	if err := h.db.ReleaseSends(ctx, id, 5, time.Now()); err != nil {
		t.Fatal(err)
	}
	if sent, _ := h.db.SentThisMonth(ctx, id, time.Now()); sent != 0 {
		t.Fatalf("usage went to %d after releasing more than was used", sent)
	}
}
