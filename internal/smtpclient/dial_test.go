package smtpclient

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

type fakePrimary struct {
	addr string

	offerSTARTTLS bool
	silent        bool

	cert              *tls.Certificate
	dropAfterSTARTTLS bool

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
			switch {
			case p.cert != nil:
				fmt.Fprint(c, "220 2.0.0 ready\r\n")
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*p.cert}})
				if tc.Handshake() != nil {
					return
				}
				c, r = tc, bufio.NewReader(tc)
			case p.dropAfterSTARTTLS:
				fmt.Fprint(c, "220 2.0.0 ready\r\n")
				return
			default:
				fmt.Fprint(c, "454 4.7.0 TLS not available\r\n")
			}
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
	encrypted, err := dialState(t, d)
	if encrypted {
		t.Error("the connection reports TLS, but the fake primary cannot do TLS")
	}
	return err
}

func dialState(t *testing.T, d *store.Domain) (encrypted bool, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, d, HelloName(d))
	if err != nil {
		return false, err
	}
	defer client.Close()
	_, encrypted = client.TLSConnectionState()
	return encrypted, client.Quit()
}

func selfSigned(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake.primary"},
		DNSNames:     []string{"fake.primary"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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

func TestOpportunisticEncryptsWithoutVerifyingTheCertificate(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: true, cert: selfSigned(t)})
	encrypted, err := dialState(t, p.domain(t, TLSOpportunistic))
	if err != nil {
		t.Fatalf("Dial(opportunistic) against a self-signed primary = %v; want the mail delivered", err)
	}
	if !encrypted {
		t.Fatal("the session fell back to plaintext; want TLS without verification, like Postfix's may level")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ehlo) != 2 || p.ehlo[1] != "xeronmx.example.com" {
		t.Fatalf("EHLO sequence = %q; want the domain's hello name after STARTTLS", p.ehlo)
	}
}

func TestOpportunisticDeliversInPlaintextWhenTheHandshakeFails(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: true, dropAfterSTARTTLS: true})
	if err := dial(t, p.domain(t, TLSOpportunistic)); err != nil {
		t.Fatalf("Dial(opportunistic) = %v; want the plaintext fallback", err)
	}
	if got := p.lastEHLO(); got != "xeronmx.example.com" {
		t.Fatalf("session identified itself as %q; want xeronmx.example.com", got)
	}
}

func TestStrictSTARTTLSRefusesAnUnverifiableCertificate(t *testing.T) {
	p := startPrimary(t, &fakePrimary{offerSTARTTLS: true, cert: selfSigned(t)})
	_, err := dialState(t, p.domain(t, TLSRequired))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("Dial(starttls) against a self-signed primary = %v; want a STARTTLS error", err)
	}
}

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
