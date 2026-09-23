package dsn

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func parse(t *testing.T, raw []byte) (*mail.Message, map[string]string) {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid message: %v\n%s", err, raw)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/report" || params["report-type"] != "delivery-status" {
		t.Fatalf("Content-Type = %q (%v); want multipart/report; report-type=delivery-status",
			msg.Header.Get("Content-Type"), err)
	}
	parts := map[string]string{}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("multipart: %v", err)
		}
		body, _ := io.ReadAll(p)
		parts[p.Header.Get("Content-Type")] = string(body)
	}
	return msg, parts
}

func TestBuildIsAWellFormedReport(t *testing.T) {
	arrival := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	raw, err := Build(Report{
		ReportingMTA: "mx2.example.test",
		QueueID:      "abc123",
		Arrival:      arrival,
		Recipient:    "alice@sender.test",
		Failures: []Failure{
			{Recipient: "bob@example.test", Status: "5.1.1", Diagnostic: "smtp; 550 5.1.1 no such user"},
			Expired("carol@example.test", 168*time.Hour),
		},
		Headers: []byte("From: alice@sender.test\r\nSubject: hello\r\n"),
	}, arrival.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	msg, parts := parse(t, raw)
	if got := msg.Header.Get("To"); got != "<alice@sender.test>" {
		t.Errorf("To = %q", got)
	}
	if got := msg.Header.Get("From"); !strings.Contains(got, "MAILER-DAEMON@mx2.example.test") {
		t.Errorf("From = %q", got)
	}
	if got := msg.Header.Get("Auto-Submitted"); got != "auto-replied" {
		t.Errorf("Auto-Submitted = %q; want auto-replied so that nothing answers it", got)
	}

	status := parts["message/delivery-status"]
	for _, want := range []string{
		"Reporting-MTA: dns; mx2.example.test",
		"Arrival-Date: Sun, 20 Sep 2026 08:00:00 +0000",
		"Final-Recipient: rfc822; bob@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 no such user",
		"Final-Recipient: rfc822; carol@example.test\r\nAction: failed\r\nStatus: 4.4.7",
	} {
		if !strings.Contains(status, want) {
			t.Errorf("delivery-status lacks %q:\n%s", want, status)
		}
	}
	if !strings.Contains(parts["text/rfc822-headers"], "Subject: hello") {
		t.Errorf("original headers missing: %q", parts["text/rfc822-headers"])
	}
	if !strings.Contains(parts["text/plain; charset=us-ascii"], "<bob@example.test>") {
		t.Errorf("the human-readable part does not name the recipient")
	}
}

func TestBuildWithoutHeaders(t *testing.T) {
	raw, err := Build(Report{
		ReportingMTA: "mx2.example.test", Recipient: "alice@sender.test",
		Failures: []Failure{Lost("bob@example.test")},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, parts := parse(t, raw)
	if _, ok := parts["text/rfc822-headers"]; ok {
		t.Fatal("a headers part was written with no headers to put in it")
	}
	if !strings.Contains(parts["message/delivery-status"], "Status: 5.3.0") {
		t.Fatal("a lost message is not reported as such")
	}
}

func TestBuildRefusesAnEmptyReport(t *testing.T) {
	if _, err := Build(Report{ReportingMTA: "mx", Failures: []Failure{Lost("b@x")}}, time.Now()); err == nil {
		t.Fatal("a report with no recipient was built")
	}
	if _, err := Build(Report{ReportingMTA: "mx", Recipient: "a@x"}, time.Now()); err == nil {
		t.Fatal("a report with no failures was built")
	}
}

func TestHostileValuesCannotAddHeaders(t *testing.T) {
	raw, err := Build(Report{
		ReportingMTA: "mx2.example.test",
		Recipient:    "alice@sender.test>\r\nBcc: victim@elsewhere.test",
		Failures: []Failure{{
			Recipient:  "bob@example.test\r\nX-Injected: yes",
			Status:     "5.1.1",
			Diagnostic: "smtp; 550 no\r\n\r\n--boundary",
		}},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := parse(t, raw)
	if msg.Header.Get("Bcc") != "" {
		t.Fatal("a recipient address added a Bcc header")
	}
	if bytes.Contains(raw, []byte("\r\nX-Injected")) || bytes.Contains(raw, []byte("\r\nBcc")) {
		t.Fatalf("a value broke onto a line of its own:\n%s", raw)
	}
}

func TestFromError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status string
		diag   string
	}{
		{"enhanced code", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"},
			"5.1.1", "smtp; 550 5.1.1 no such user"},
		{"no enhanced code", &smtp.SMTPError{Code: 554, Message: "refused"}, "5.0.0", "smtp; 554 5.0.0 refused"},
		{"wrapped", errors.Join(errors.New("RCPT TO bob"), &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 2, 2}, Message: "mailbox full"}),
			"5.2.2", "smtp; 552 5.2.2 mailbox full"},
		{"not an smtp reply", errors.New("body unreadable"), "5.0.0", "X-XeronMX; body unreadable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := FromError("bob@example.test", tc.err)
			if f.Status != tc.status || f.Diagnostic != tc.diag || f.Recipient != "bob@example.test" {
				t.Fatalf("FromError = %+v; want status %q, diagnostic %q", f, tc.status, tc.diag)
			}
		})
	}
}

func TestHeadersOf(t *testing.T) {
	msg := "From: a@b\r\nSubject: s\r\n\r\nBody: not a header\r\n"
	if got := string(HeadersOf(strings.NewReader(msg))); got != "From: a@b\r\nSubject: s\r\n" {
		t.Fatalf("HeadersOf = %q; want the header block only", got)
	}
	bare := "From: a@b\nSubject: s\n\nbody\n"
	if got := string(HeadersOf(strings.NewReader(bare))); got != "From: a@b\r\nSubject: s\r\n" {
		t.Fatalf("HeadersOf(bare LF) = %q", got)
	}
	huge := "X-Big: " + strings.Repeat("a", 200<<10) + "\r\n\r\n"
	if got := HeadersOf(strings.NewReader(huge)); len(got) > maxHeaderBytes+2 {
		t.Fatalf("HeadersOf read %d bytes; want it capped at %d", len(got), maxHeaderBytes)
	}
}
