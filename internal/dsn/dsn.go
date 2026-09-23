package dsn

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
)

const maxHeaderBytes = 64 << 10

type Failure struct {
	Recipient  string
	Status     string
	Diagnostic string
}

type Report struct {
	ReportingMTA string
	QueueID      string
	Arrival      time.Time
	Recipient    string
	Failures     []Failure
	Headers      []byte
}

func FromError(rcpt string, err error) Failure {
	var reply *smtp.SMTPError
	if errors.As(err, &reply) {
		status := fmt.Sprintf("%d.0.0", reply.Code/100)
		if c := reply.EnhancedCode; c[0] == 4 || c[0] == 5 {
			status = fmt.Sprintf("%d.%d.%d", c[0], c[1], c[2])
		}
		return Failure{
			Recipient:  rcpt,
			Status:     status,
			Diagnostic: fmt.Sprintf("smtp; %d %s %s", reply.Code, status, reply.Message),
		}
	}
	return Failure{Recipient: rcpt, Status: "5.0.0", Diagnostic: "X-XeronMX; " + err.Error()}
}

func Expired(rcpt string, held time.Duration) Failure {
	return Failure{
		Recipient: rcpt,
		Status:    "4.4.7",
		Diagnostic: fmt.Sprintf("X-XeronMX; the destination server did not accept the message within %s",
			held.Round(time.Hour)),
	}
}

func Lost(rcpt string) Failure {
	return Failure{
		Recipient:  rcpt,
		Status:     "5.3.0",
		Diagnostic: "X-XeronMX; the message could not be read back from the backup server's spool",
	}
}

func HeadersOf(r io.Reader) []byte {
	br := bufio.NewReader(io.LimitReader(r, maxHeaderBytes))
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
		out.WriteString(strings.TrimRight(line, "\r\n") + "\r\n")
		if err != nil {
			break
		}
	}
	return out.Bytes()
}

func Build(r Report, now time.Time) ([]byte, error) {
	if r.Recipient == "" {
		return nil, errors.New("dsn: a report needs somewhere to go")
	}
	if len(r.Failures) == 0 {
		return nil, errors.New("dsn: nothing to report")
	}
	boundary, err := token()
	if err != nil {
		return nil, err
	}
	nonce, err := token()
	if err != nil {
		return nil, err
	}
	host := clean(r.ReportingMTA)

	var b bytes.Buffer
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\r\n", args...) }

	w("From: Mail Delivery System <MAILER-DAEMON@%s>", host)
	w("To: <%s>", clean(r.Recipient))
	w("Subject: Undelivered Mail Returned to Sender")
	w("Date: %s", now.UTC().Format(time.RFC1123Z))
	w("Message-ID: <%s.%s@%s>", clean(r.QueueID), nonce, host)
	w("Auto-Submitted: auto-replied")
	w("MIME-Version: 1.0")
	w("Content-Type: multipart/report; report-type=delivery-status; boundary=\"%s\"", boundary)
	w("")
	w("This is a MIME-formatted message delivery status notification.")
	w("")

	w("--%s", boundary)
	w("Content-Type: text/plain; charset=us-ascii")
	w("")
	w("This is the mail system at %s, a backup mail exchanger.", host)
	w("")
	w("Your message was accepted here while the destination server was")
	w("unreachable, but it could not be delivered to the following")
	w("recipients. The report below says why.")
	w("")
	for _, f := range r.Failures {
		w("  <%s>: %s", clean(f.Recipient), clean(f.Diagnostic))
	}
	w("")

	w("--%s", boundary)
	w("Content-Type: message/delivery-status")
	w("")
	w("Reporting-MTA: dns; %s", host)
	if r.QueueID != "" {
		w("X-XeronMX-Queue-ID: %s", clean(r.QueueID))
	}
	if !r.Arrival.IsZero() {
		w("Arrival-Date: %s", r.Arrival.UTC().Format(time.RFC1123Z))
	}
	for _, f := range r.Failures {
		w("")
		w("Final-Recipient: rfc822; %s", clean(f.Recipient))
		w("Action: failed")
		w("Status: %s", clean(f.Status))
		w("Diagnostic-Code: %s", clean(f.Diagnostic))
	}
	w("")

	if len(r.Headers) > 0 {
		w("--%s", boundary)
		w("Content-Type: text/rfc822-headers")
		w("")
		b.Write(r.Headers)
		w("")
	}
	w("--%s--", boundary)
	return b.Bytes(), nil
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 && r != '\t' || r > 0x7e {
			return -1
		}
		return r
	}, s)
}

func token() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("dsn: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
