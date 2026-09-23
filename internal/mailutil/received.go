package mailutil

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const MaxHops = 50

type Trace struct {
	Helo      string
	Remote    string
	By        string
	Protocol  string
	ID        string
	Recipient string
	At        time.Time
}

func (t Trace) Header() string {
	ip := t.Remote
	if host, _, err := net.SplitHostPort(t.Remote); err == nil {
		ip = host
	}
	literal := "[" + ip + "]"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		literal = "[IPv6:" + ip + "]"
	}

	helo := traceToken(t.Helo)
	if helo == "" {
		helo = "unknown"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Received: from %s (%s)\r\n", helo, literal)
	fmt.Fprintf(&b, "\tby %s (XeronMX) with %s id %s", traceToken(t.By), t.Protocol, t.ID)
	if rcpt := traceToken(t.Recipient); rcpt != "" {
		fmt.Fprintf(&b, "\r\n\tfor <%s>", rcpt)
	}
	fmt.Fprintf(&b, "; %s\r\n", t.At.Format(time.RFC1123Z))
	return b.String()
}

func Protocol(tls, authenticated bool) string {
	p := "ESMTP"
	if tls {
		p += "S"
	}
	if authenticated {
		p += "A"
	}
	return p
}

func traceToken(s string) string {
	if len(s) > 255 {
		s = s[:255]
	}
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune("()[]<>;\\\"", r) {
			return -1
		}
		return r
	}, s)
}

func CountReceived(head []byte) int { return countHeader(head, "received") }

func HasHeader(head []byte, name string) bool { return countHeader(head, name) > 0 }

func countHeader(head []byte, name string) int {
	prefix := name + ":"
	n := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n") {
		if line == "" {
			break
		}
		if len(line) >= len(prefix) && strings.EqualFold(line[:len(prefix)], prefix) {
			n++
		}
	}
	return n
}

func Hostname(configured string) string {
	if configured != "" {
		return configured
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}
