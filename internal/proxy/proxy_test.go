package proxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func TestParseTrusted(t *testing.T) {
	nets, err := ParseTrusted([]string{"10.0.0.0/8", " 192.0.2.7 ", "2001:db8::/32", "2001:db8::1", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 4 {
		t.Fatalf("parsed %d ranges, want 4", len(nets))
	}
	if got := nets[1].String(); got != "192.0.2.7/32" {
		t.Fatalf("a bare IPv4 address became %s, want /32", got)
	}
	if got := nets[3].String(); got != "2001:db8::1/128" {
		t.Fatalf("a bare IPv6 address became %s, want /128", got)
	}
	for _, bad := range []string{"not-an-address", "10.0.0.0/33", "300.1.1.1"} {
		if _, err := ParseTrusted([]string{bad}); err == nil {
			t.Errorf("ParseTrusted(%q) accepted it", bad)
		}
	}
}

type accepted struct {
	remote string
	line   string
	err    error
}

func serve(t *testing.T, trusted []string) (string, <-chan accepted) {
	t.Helper()
	nets, err := ParseTrusted(trusted)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(raw, nets)
	t.Cleanup(func() { ln.Close() })

	out := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			out <- accepted{err: err}
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		remote := c.RemoteAddr().String()
		fmt.Fprint(c, "220 ready\r\n")
		line, err := bufio.NewReader(c).ReadString('\n')
		out <- accepted{remote: remote, line: strings.TrimSpace(line), err: err}
	}()
	return raw.Addr().String(), out
}

func dialAndSend(t *testing.T, addr string, header []byte, line string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if header != nil {
		if _, err := c.Write(header); err != nil {
			t.Fatal(err)
		}
	}
	bufio.NewReader(c).ReadString('\n')
	fmt.Fprint(c, line+"\r\n")
}

func header(t *testing.T, version byte) []byte {
	t.Helper()
	h := &proxyproto.Header{
		Version:           version,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40123},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 25},
	}
	b, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestATrustedBalancerHandsOverTheClientAddress(t *testing.T) {
	for _, version := range []byte{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			addr, out := serve(t, []string{"127.0.0.1"})
			dialAndSend(t, addr, header(t, version), "EHLO client.example")
			got := <-out
			if got.err != nil {
				t.Fatal(got.err)
			}
			if got.remote != "203.0.113.7:40123" {
				t.Fatalf("remote = %s; want the client's address from the header", got.remote)
			}
			if got.line != "EHLO client.example" {
				t.Fatalf("first line = %q; the header must be consumed, not passed on", got.line)
			}
		})
	}
}

func TestATrustedPeerWithoutAHeaderIsRefused(t *testing.T) {
	addr, out := serve(t, []string{"127.0.0.1"})
	dialAndSend(t, addr, nil, "EHLO client.example")
	got := <-out
	if got.err == nil {
		t.Fatalf("a trusted peer without a header was served (remote %s, line %q); a balancer that stopped sending headers would make every sender look like the balancer", got.remote, got.line)
	}
}

func TestAnUntrustedPeerCannotClaimAnotherAddress(t *testing.T) {
	addr, out := serve(t, []string{"10.0.0.0/8"})
	dialAndSend(t, addr, header(t, 1), "EHLO client.example")
	got := <-out
	if got.err != nil {
		t.Fatal(got.err)
	}
	if !strings.HasPrefix(got.remote, "127.0.0.1:") {
		t.Fatalf("remote = %s; an untrusted peer spoofed its address with a PROXY header", got.remote)
	}
	if !strings.HasPrefix(got.line, "PROXY TCP4 203.0.113.7") {
		t.Fatalf("first line = %q; the header must reach the SMTP server untouched, where it is an invalid command", got.line)
	}
}

func TestAnUntrustedClientIsServedFirstLikeAnyOther(t *testing.T) {
	addr, out := serve(t, []string{"10.0.0.0/8"})
	start := time.Now()
	dialAndSend(t, addr, nil, "EHLO client.example")
	got := <-out
	if got.err != nil || got.line != "EHLO client.example" {
		t.Fatalf("got %+v", got)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("the banner took %v: reading the remote address must not wait for a header SMTP clients never send", waited)
	}
}

func TestNoTrustedRangesMeansNoProxyProtocol(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if Listen(raw, nil) != raw {
		t.Fatal("with no trusted ranges the listener must be returned unwrapped")
	}
}
