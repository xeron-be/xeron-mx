package smtpclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

// fakePrimary is just enough of an SMTP server to exercise the TLS decisions
// Dial makes. It never completes a TLS handshake: STARTTLS is either not
// offered or refused with 454, which is what a primary with a broken or
// missing certificate does.
type fakePrimary struct {
	addr string

	offerSTARTTLS bool
	silent        bool // accept the connection and never greet

	mu   sync.Mutex
	ehlo []string
}

func startPrimary(t *testing.T, p *fakePrimary) *fakePrimary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.addr = ln.Addr().String()

	var conns sync.WaitGroup
	t.Cleanup(func() {
		ln.Close()
		conns.Wait()
	})
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })

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
				if p.silent {
					<-stop
					return
				}
				p.serve(c)
			}()
		}
	}()
	return p
}

func (p *fakePrimary) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	fmt.Fprint(c, "220 fake.primary ESMTP\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			p.mu.Lock()
			p.ehlo = append(p.ehlo, arg)
			p.mu.Unlock()
			if p.offerSTARTTLS {
				fmt.Fprint(c, "250-fake.primary\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
			} else {
				fmt.Fprint(c, "250-fake.primary\r\n250 PIPELINING\r\n")
			}
		case "STARTTLS":
			fmt.Fprint(c, "454 4.7.0 TLS not available\r\n")
		case "QUIT":
			fmt.Fprint(c, "221 2.0.0 bye\r\n")
			return
		default:
			fmt.Fprint(c, "502 5.5.2 not implemented\r\n")
		}
	}
}

func (p *fakePrimary) lastEHLO() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ehlo) == 0 {
		return ""
	}
	return p.ehlo[len(p.ehlo)-1]
}

func (p *fakePrimary) domain(t *testing.T, mode string) *store.Domain {
	t.Helper()
	host, port, err := net.SplitHostPort(p.addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	return &store.Domain{Name: "example.com", PrimaryHost: host, PrimaryPort: n, PrimaryTLS: mode}
}

func dial(t *testing.T, d *store.Domain) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, d, HelloName(d))
	if err != nil {
		return err
	}
	defer client.Close()
	if _, isTLS := client.TLSConnectionState(); isTLS {
		t.Error("the connection reports TLS, but the fake primary cannot do TLS")
	}
	return client.Quit()
}

func TestNoneNeverAttemptsSTARTTLS(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: true})
	if err := dial(t, p.domain(t, TLSNone)); err != nil {
		t.Fatalf("Dial(none) = %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ehlo) != 1 || p.ehlo[0] != "xeronmx.example.com" {
		t.Fatalf("EHLO sequence = %q; want a single EHLO xeronmx.example.com", p.ehlo)
	}
}

func TestOpportunisticDeliversInPlaintextWithoutSTARTTLS(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: false})
	if err := dial(t, p.domain(t, TLSOpportunistic)); err != nil {
		t.Fatalf("Dial(opportunistic) = %v", err)
	}
	if got := p.lastEHLO(); got != "xeronmx.example.com" {
		t.Fatalf("session identified itself as %q; want xeronmx.example.com", got)
	}
}

func TestOpportunisticDeliversInPlaintextWhenSTARTTLSFails(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: true})
	if err := dial(t, p.domain(t, TLSOpportunistic)); err != nil {
		t.Fatalf("Dial(opportunistic) = %v", err)
	}
	if got := p.lastEHLO(); got != "xeronmx.example.com" {
		t.Fatalf("session identified itself as %q; want xeronmx.example.com", got)
	}
}

// An empty mode is what a domain created before `primary_tls` existed carries.
// It has to behave as opportunistic: treating it as strict would silently stop
// delivery to every primary without STARTTLS.
func TestEmptyModeIsOpportunistic(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: false})
	if err := dial(t, p.domain(t, "")); err != nil {
		t.Fatalf("Dial(\"\") = %v; want the opportunistic fallback", err)
	}
}

func TestStrictSTARTTLSRefusesPlaintext(t *testing.T) {
	for name, offer := range map[string]bool{"not offered": false, "refused": true} {
		t.Run(name, func(t *testing.T) {
			p := startPrimary(t, &fakePrimary{offerSTARTTLS: offer})
			err := dial(t, p.domain(t, TLSRequired))
			if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
				t.Fatalf("Dial(starttls) = %v; want a STARTTLS error", err)
			}
		})
	}
}

func TestImplicitTLSAgainstAPlaintextServerFails(t *testing.T) {
	p := startPrimary(t, &fakePrimary{})
	if err := dial(t, p.domain(t, TLSImplicit)); err == nil {
		t.Fatal("Dial(tls) against a plaintext server succeeded")
	}
}

func TestUnreachablePrimary(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	d := &store.Domain{Name: "example.com", PrimaryHost: "127.0.0.1", PrimaryPort: addr.Port, PrimaryTLS: TLSNone}
	err = dial(t, d)
	if err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("Dial to a closed port = %v; want a connect error", err)
	}
}

// A primary that accepts the connection and then says nothing (overloaded, or
// a tarpit) must not hold the caller past its context. go-smtp sets its own
// five-minute deadline on every command, so a deadline set on the connection
// beforehand is not enough on its own.
func TestDialHonoursTheContextWhenThePrimaryStalls(t *testing.T) {
	for _, mode := range []string{TLSNone, TLSOpportunistic, TLSRequired} {
		t.Run(mode, func(t *testing.T) {
			p := startPrimary(t, &fakePrimary{silent: true})

			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start := time.Now()
			client, err := Dial(ctx, p.domain(t, mode), "xeronmx.example.com")
			if err == nil {
				client.Close()
				t.Fatal("Dial to a silent primary succeeded")
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("Dial returned after %v; want it bounded by the 300ms context", elapsed)
			}
			// This string ends up as the primary's last error in the panel.
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Dial error = %v; want it to name the expired deadline", err)
			}
		})
	}
}

func TestValidTLSMode(t *testing.T) {
	for _, m := range []string{TLSNone, TLSOpportunistic, TLSRequired, TLSImplicit} {
		if !ValidTLSMode(m) {
			t.Errorf("ValidTLSMode(%q) = false", m)
		}
	}
	for _, m := range []string{"", "STARTTLS", "ssl", "required"} {
		if ValidTLSMode(m) {
			t.Errorf("ValidTLSMode(%q) = true", m)
		}
	}
}

func TestHelloName(t *testing.T) {
	if got := HelloName(&store.Domain{Name: "example.org"}); got != "xeronmx.example.org" {
		t.Fatalf("HelloName = %q", got)
	}
}
