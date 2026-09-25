package smtpclient

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

func TestIsPublic(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":                true,
		"37.187.39.160":          true,
		"172.15.255.255":         true,
		"172.32.0.0":             true,
		"100.63.255.255":         true,
		"100.128.0.0":            true,
		"2001:4860:4860::8888":   true,
		"2001:41d0:404:200::1":   true,
		"::ffff:8.8.8.8":         true,
		"127.0.0.1":              false,
		"127.8.9.10":             false,
		"10.1.2.3":               false,
		"172.16.0.1":             false,
		"172.31.255.255":         false,
		"192.168.1.1":            false,
		"100.64.0.1":             false,
		"169.254.169.254":        false,
		"0.0.0.0":                false,
		"0.1.2.3":                false,
		"255.255.255.255":        false,
		"224.0.0.1":              false,
		"192.0.2.10":             false,
		"198.18.0.1":             false,
		"::":                     false,
		"::1":                    false,
		"::ffff:127.0.0.1":       false,
		"::ffff:10.0.0.1":        false,
		"fe80::1":                false,
		"fd00::1":                false,
		"fc12::1":                false,
		"ff02::1":                false,
		"2001:db8::1":            false,
		"2002:7f00:1::1":         false,
		"64:ff9b:1::a00:1":       false,
		"fe80::1%eth0":           false,
		"2001:0:4136:e378::1234": false,
	}
	for s, want := range cases {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		if got := IsPublic(addr); got != want {
			t.Errorf("IsPublic(%s) = %v; want %v", s, got, want)
		}
	}
	if IsPublic(netip.Addr{}) {
		t.Error("the zero address counts as public")
	}
}

func countingListener(t *testing.T, network, address string) (int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", address, err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Write([]byte("220 fake\r\n"))
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port, &accepted
}

func dialWith(t *testing.T, host string, port int, mode string, opts ...Option) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := &store.Domain{Name: "example.com", PrimaryHost: host, PrimaryPort: port, PrimaryTLS: mode}
	client, err := Dial(ctx, d, HelloName(d), opts...)
	if err == nil {
		client.Close()
	}
	return err
}

func TestPublicOnlyRefusesAPrivatePrimaryWithoutConnecting(t *testing.T) {
	for _, mode := range []string{TLSNone, TLSOpportunistic, TLSRequired, TLSImplicit} {
		t.Run(mode, func(t *testing.T) {
			port, accepted := countingListener(t, "tcp4", "127.0.0.1:0")
			err := dialWith(t, "127.0.0.1", port, mode, PublicOnly(true))
			if !errors.Is(err, ErrNonPublicAddress) {
				t.Fatalf("Dial = %v; want ErrNonPublicAddress", err)
			}
			time.Sleep(50 * time.Millisecond)
			if n := accepted.Load(); n != 0 {
				t.Fatalf("the private primary received %d connection(s); want none", n)
			}
		})
	}
}

func TestPublicOnlyRefusesIPv6Loopback(t *testing.T) {
	port, accepted := countingListener(t, "tcp6", "[::1]:0")
	if err := dialWith(t, "::1", port, TLSNone, PublicOnly(true)); !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("Dial = %v; want ErrNonPublicAddress", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("::1 received %d connection(s); want none", n)
	}
}

func TestPublicOnlyChecksTheResolvedAddressOfAName(t *testing.T) {
	port, accepted := countingListener(t, "tcp4", "127.0.0.1:0")
	if err := dialWith(t, "localhost", port, TLSNone, PublicOnly(true)); !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("Dial(localhost) = %v; want ErrNonPublicAddress", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("a name resolving to loopback reached the listener %d time(s)", n)
	}
}

func TestPrivatePrimaryIsReachableWhenAllowed(t *testing.T) {
	for _, opts := range [][]Option{nil, {PublicOnly(false)}} {
		port, accepted := countingListener(t, "tcp4", "127.0.0.1:0")
		err := dialWith(t, "127.0.0.1", port, TLSNone, opts...)
		if errors.Is(err, ErrNonPublicAddress) {
			t.Fatalf("Dial with %d option(s) refused a private primary", len(opts))
		}
		time.Sleep(50 * time.Millisecond)
		if accepted.Load() == 0 {
			t.Fatalf("Dial with %d option(s) never reached the listener", len(opts))
		}
	}
}
