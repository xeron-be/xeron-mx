package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/ses"
	"github.com/xeron-be/xeron-mx/internal/ses/sestest"
)

func TestSendingCanBeSuspendedAndResumedByHand(t *testing.T) {
	a := newTestAPI(t)
	a.SetOutbound(config.OutboundConfig{Enabled: true})
	cookie := a.setup(t)
	path := a.addSESDomain(t, cookie, "client.example")

	if got := decodeBody(t, a.do(t, "GET", path, nil, cookie)); got["sending_level"] != "ok" {
		t.Fatalf("domain = %v", got)
	}
	rec := a.do(t, "POST", path+"/sending/suspend", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("suspend returned %d: %s", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, rec); got["suspended"] != true || got["suspended_reason"] != "manual" || got["monitored"] != false {
		t.Fatalf("after suspend: %v", got)
	}
	if rec := a.do(t, "POST", path+"/sending/suspend", nil, cookie); rec.Code != http.StatusConflict {
		t.Fatalf("a second suspend returned %d", rec.Code)
	}
	if got := decodeBody(t, a.do(t, "GET", path, nil, cookie)); got["sending_level"] != "suspended" {
		t.Fatalf("domain = %v", got)
	}
	if rec := a.do(t, "POST", path+"/sending/resume", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("resume returned %d", rec.Code)
	}
	if rec := a.do(t, "POST", path+"/sending/resume", nil, cookie); rec.Code != http.StatusConflict ||
		decodeBody(t, rec)["error"] != ErrSendingNotSuspended {
		t.Fatalf("resuming a running domain returned %d", rec.Code)
	}
}

func TestSendingReputationIsReported(t *testing.T) {
	a := newTestAPI(t)
	a.SetOutbound(config.OutboundConfig{Enabled: true})
	cookie := a.setup(t)
	a.withSES(t)
	queue := &sestest.Queue{}
	mon := ses.NewMonitor(queue, "https://sqs.eu-west-3.amazonaws.com/1/q", a.db,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, config.Default().Outbound.SES.Protection)
	a.SetReputation(mon)
	path := a.addSESDomain(t, cookie, "client.example")

	d, _ := a.db.DomainByName(context.Background(), "client.example")
	a.db.RecordSent(context.Background(), d.ID, 100, time.Now())
	queue.Push(
		sestest.Bounce("a@client.example", "x@far.example", "1"),
		sestest.Bounce("a@client.example", "y@far.example", "2"),
		sestest.Bounce("a@client.example", "z@far.example", "3"),
	)
	if _, err := mon.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := decodeBody(t, a.do(t, "GET", path+"/sending", nil, cookie))
	if got["monitored"] != true || got["sent"] != float64(100) || got["bounces"] != float64(3) ||
		got["bounce_percent"] != float64(3) || got["level"] != "warning" {
		t.Fatalf("sending = %v", got)
	}
	if list, _ := got["feedback"].([]any); len(list) != 3 {
		t.Fatalf("feedback = %v", got["feedback"])
	}
	status := decodeBody(t, a.do(t, "GET", "/api/v1/ses", nil, cookie))
	if events, _ := status["events"].(map[string]any); events["recorded"] != float64(3) {
		t.Fatalf("ses status = %v", status)
	}
}
