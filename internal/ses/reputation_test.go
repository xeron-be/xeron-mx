package ses_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/ses"
	"github.com/xeron-be/xeron-mx/internal/ses/sestest"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type monitorFixture struct {
	db     *store.DB
	queue  *sestest.Queue
	m      *ses.Monitor
	notify *recorder
	n      int
}

func newMonitor(t *testing.T) *monitorFixture {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &monitorFixture{db: db, queue: &sestest.Queue{}, notify: &recorder{}}
	f.m = ses.NewMonitor(f.queue, "https://sqs.eu-west-3.amazonaws.com/1/q", db,
		slog.New(slog.NewTextHandler(io.Discard, nil)), f.notify, config.Default().Outbound.SES.Protection)
	return f
}

func (f *monitorFixture) domain(t *testing.T, name string) *store.Domain {
	t.Helper()
	id, err := f.db.CreateDomain(context.Background(), &store.Domain{
		Name: name, PrimaryHost: "mail." + name, PrimaryPort: 25, PrimaryTLS: "starttls",
		RetentionHours: 168, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := f.db.DomainByID(context.Background(), id)
	return d
}

func (f *monitorFixture) sent(t *testing.T, d *store.Domain, n int) {
	t.Helper()
	if err := f.db.RecordSent(context.Background(), d.ID, n, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func (f *monitorFixture) bounces(t *testing.T, sender string, n int) {
	for range n {
		f.n++
		f.queue.Push(sestest.Bounce(sender, fmt.Sprintf("gone%d@far.example", f.n), fmt.Sprintf("fb%d", f.n)))
	}
}

func (f *monitorFixture) complaints(t *testing.T, sender string, n int) {
	for range n {
		f.n++
		f.queue.Push(sestest.Complaint(sender, fmt.Sprintf("angry%d@far.example", f.n), fmt.Sprintf("fc%d", f.n)))
	}
}

func (f *monitorFixture) drain(t *testing.T) {
	t.Helper()
	for range 10 {
		n, err := f.m.Poll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
}

func (f *monitorFixture) state(t *testing.T, d *store.Domain) *store.SendingState {
	t.Helper()
	st, err := f.db.SendingStateFor(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAFewBouncesOnAHealthyVolumeChangeNothing(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	f.sent(t, d, 1000)
	f.bounces(t, "a@client.example", 6)
	f.drain(t)
	if f.state(t, d).Suspended() || len(f.notify.events) != 0 {
		t.Fatalf("0.6%% bounces suspended or warned: %v", f.notify.events)
	}
}

func TestOneMistypedAddressIsNotEnough(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	f.sent(t, d, 10)
	f.bounces(t, "a@client.example", 2)
	f.drain(t)
	if f.state(t, d).Suspended() || len(f.notify.events) != 0 {
		t.Fatalf("two bounces, under the minimum, acted on: %v", f.notify.events)
	}
}

func TestBouncesWarnThenSuspend(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	f.sent(t, d, 100)

	f.bounces(t, "a@client.example", 3)
	f.drain(t)
	if !slices.Equal(f.notify.events, []string{store.EventSendingWarning}) || f.state(t, d).Suspended() {
		t.Fatalf("3%% with three bounces: events %v", f.notify.events)
	}

	f.bounces(t, "a@client.example", 1)
	f.drain(t)
	if len(f.notify.events) != 1 {
		t.Fatalf("the warning was repeated: %v", f.notify.events)
	}

	f.bounces(t, "b@client.example", 1)
	f.drain(t)
	st := f.state(t, d)
	if !st.Suspended() || st.SuspendedReason != ses.ReasonBounces || st.SuspendedBy != "auto" {
		t.Fatalf("5%% with five bounces: state %+v", st)
	}
	if f.notify.events[len(f.notify.events)-1] != store.EventSendingSuspended {
		t.Fatalf("events = %v", f.notify.events)
	}

	f.bounces(t, "a@client.example", 3)
	f.drain(t)
	n := 0
	for _, e := range f.notify.events {
		if e == store.EventSendingSuspended {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("suspended announced %d times", n)
	}
}

func TestTwoComplaintsSuspendWhateverTheVolume(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	f.sent(t, d, 5000)
	f.complaints(t, "a@client.example", 1)
	f.drain(t)
	if f.state(t, d).Suspended() || !slices.Contains(f.notify.events, store.EventSendingWarning) {
		t.Fatalf("one complaint: events %v", f.notify.events)
	}
	f.complaints(t, "a@client.example", 1)
	f.drain(t)
	if st := f.state(t, d); !st.Suspended() || st.SuspendedReason != ses.ReasonComplaints {
		t.Fatalf("two complaints: state %+v", st)
	}
}

func TestDomainsAreJudgedApart(t *testing.T) {
	f := newMonitor(t)
	bad := f.domain(t, "bad.example")
	good := f.domain(t, "good.example")
	f.sent(t, bad, 20)
	f.sent(t, good, 20)
	f.bounces(t, "x@bad.example", 6)
	f.drain(t)
	if !f.state(t, bad).Suspended() || f.state(t, good).Suspended() {
		t.Fatal("one domain's bounces affected the other")
	}
}

func TestAnEventDeliveredTwiceCountsOnce(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	ev := sestest.Bounce("a@client.example", "gone@far.example", "same")
	f.queue.Push(ev, ev, ev)
	f.drain(t)
	w, _, err := f.m.Window(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if w.Bounces != 1 {
		t.Fatalf("bounces = %d; want the duplicate ignored", w.Bounces)
	}
	if len(f.queue.Deleted) != 3 {
		t.Fatalf("deleted %v; want every copy removed from the queue", f.queue.Deleted)
	}
}

func TestFeedbackNobodyOwnsIsDropped(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	f.queue.Push(
		sestest.Bounce("MAILER-DAEMON@client.example", "x@far.example", "a"),
		sestest.Bounce("someone@unknown.example", "x@far.example", "b"),
		"{not json",
		"Successfully validated SNS topic for Amazon SES event publishing.",
	)
	f.drain(t)
	w, _, _ := f.m.Window(context.Background(), d)
	if w.Bounces != 0 {
		t.Fatalf("bounces = %d", w.Bounces)
	}
	if len(f.queue.Deleted) != 4 {
		t.Fatalf("deleted %v; unreadable or foreign messages must not loop forever", f.queue.Deleted)
	}
}

func TestResumingStartsTheCountAfresh(t *testing.T) {
	f := newMonitor(t)
	d := f.domain(t, "client.example")
	f.sent(t, d, 10)
	f.complaints(t, "a@client.example", 2)
	f.drain(t)
	if !f.state(t, d).Suspended() {
		t.Fatal("not suspended")
	}
	if ok, err := f.db.ResumeSending(context.Background(), d.ID, time.Now().Add(time.Second)); !ok || err != nil {
		t.Fatalf("resume = %v, %v", ok, err)
	}
	if err := f.m.Evaluate(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if f.state(t, d).Suspended() {
		t.Fatal("suspended again by the complaints it was resumed from")
	}
}

func TestAnUnreachableQueueIsReported(t *testing.T) {
	f := newMonitor(t)
	f.queue.Err = errors.New("AccessDenied")
	if _, err := f.m.Poll(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if st := f.m.Status(); st.LastError != "AccessDenied" || st.LastPollAt == nil {
		t.Fatalf("status = %+v", st)
	}
}

func TestAssess(t *testing.T) {
	p := config.Default().Outbound.SES.Protection
	cases := []struct {
		sent, bounces, complaints int64
		want                      string
	}{
		{0, 0, 0, ses.LevelOK},
		{100, 2, 0, ses.LevelOK},
		{100, 3, 0, ses.LevelWarning},
		{100, 5, 0, ses.LevelSuspended},
		{1000, 10, 0, ses.LevelOK},
		{0, 5, 0, ses.LevelSuspended},
		{10000, 0, 1, ses.LevelWarning},
		{10000, 0, 2, ses.LevelSuspended},
	}
	for _, c := range cases {
		got, _ := ses.Assess(p, &store.SendingWindow{Sent: c.sent, Bounces: c.bounces, Complaints: c.complaints})
		if got != c.want {
			t.Errorf("sent %d, bounces %d, complaints %d: %s; want %s", c.sent, c.bounces, c.complaints, got, c.want)
		}
	}
	if got := ses.BouncePercent(&store.SendingWindow{Sent: 300, Bounces: 7}); got != 2.3 {
		t.Errorf("bounce percent = %v", got)
	}
}
