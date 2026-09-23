package mailutil

import (
	"net/mail"
	"strings"
	"testing"
	"time"
)

var traceTime = time.Date(2026, 9, 23, 14, 57, 57, 0, time.UTC)

func TestTraceHeaderRecordsTheOriginalHop(t *testing.T) {
	got := Trace{
		Helo:      "mail-ej2-f24.google.com",
		Remote:    "74.125.228.152:32990",
		By:        "backup.mx.xeron.be",
		Protocol:  Protocol(true, false),
		ID:        "b8672462937ca0a09ed387460f552941",
		Recipient: "alice@mx.xeron.be",
		At:        traceTime,
	}.Header()

	want := "Received: from mail-ej2-f24.google.com ([74.125.228.152])\r\n" +
		"\tby backup.mx.xeron.be (XeronMX) with ESMTPS id b8672462937ca0a09ed387460f552941\r\n" +
		"\tfor <alice@mx.xeron.be>; Wed, 23 Sep 2026 14:57:57 +0000\r\n"
	if got != want {
		t.Fatalf("Header() =\n%q\nwant\n%q", got, want)
	}

	msg, err := mail.ReadMessage(strings.NewReader(got + "\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("the header does not parse: %v", err)
	}
	if !strings.Contains(msg.Header.Get("Received"), "[74.125.228.152]") {
		t.Fatalf("parsed Received = %q", msg.Header.Get("Received"))
	}
}

func TestTraceHeaderWithoutRecipientAndOverIPv6(t *testing.T) {
	got := Trace{
		Helo:     "client.example",
		Remote:   "[2001:db8::1]:25",
		By:       "mx.example",
		Protocol: Protocol(false, false),
		ID:       "abc",
		At:       traceTime,
	}.Header()
	if !strings.HasPrefix(got, "Received: from client.example ([IPv6:2001:db8::1])\r\n") {
		t.Fatalf("Header() = %q", got)
	}
	if strings.Contains(got, "for <") {
		t.Fatalf("Header() names a recipient that was not given: %q", got)
	}
	if !strings.Contains(got, "with ESMTP id abc; ") {
		t.Fatalf("Header() = %q", got)
	}
}

func TestTraceHeaderCannotBeInjectedThroughTheGreeting(t *testing.T) {
	got := Trace{
		Helo:     "evil\r\nX-Injected: yes (fake) [1.2.3.4]",
		Remote:   "192.0.2.1:1234",
		By:       "mx.example",
		Protocol: "ESMTP",
		ID:       "abc",
		At:       traceTime,
	}.Header()
	if strings.Count(got, "\r\n") != 2 || strings.Contains(got, "X-Injected: yes") {
		t.Fatalf("a hostile EHLO changed the header's shape: %q", got)
	}
	if !strings.HasPrefix(got, "Received: from evilX-Injected:yesfake1.2.3.4 ([192.0.2.1])") {
		t.Fatalf("Header() = %q", got)
	}

	if got := (Trace{Remote: "192.0.2.1:1", By: "mx.example", Protocol: "ESMTP", ID: "a", At: traceTime}).Header(); !strings.HasPrefix(got, "Received: from unknown ([192.0.2.1])") {
		t.Fatalf("empty EHLO: %q", got)
	}
}

func TestProtocol(t *testing.T) {
	for _, c := range []struct {
		tls, auth bool
		want      string
	}{{false, false, "ESMTP"}, {true, false, "ESMTPS"}, {true, true, "ESMTPSA"}, {false, true, "ESMTPA"}} {
		if got := Protocol(c.tls, c.auth); got != c.want {
			t.Errorf("Protocol(%v, %v) = %q, want %q", c.tls, c.auth, got, c.want)
		}
	}
}

func TestCountReceivedStopsAtTheBody(t *testing.T) {
	head := "Received: from a\r\n\tby b; x\r\nreceived: from c\r\nSubject: hi\r\nX-Received: no\r\n\r\nReceived: in the body\r\n"
	if got := CountReceived([]byte(head)); got != 2 {
		t.Fatalf("CountReceived = %d, want 2", got)
	}
}
