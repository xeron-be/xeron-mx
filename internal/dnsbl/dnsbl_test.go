package dnsbl

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

func TestReverseIPv4(t *testing.T) {
	ip := net.ParseIP("198.51.100.1")
	rev := ReverseIPv4(ip)
	if rev != "1.100.51.198" {
		t.Fatalf("expected 1.100.51.198, got %q", rev)
	}

	revGeneral := ReverseIP(ip)
	if revGeneral != "1.100.51.198" {
		t.Fatalf("expected 1.100.51.198, got %q", revGeneral)
	}
}

func TestReverseIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	rev := ReverseIPv6(ip)
	expected := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	if rev != expected {
		t.Fatalf("expected %q, got %q", expected, rev)
	}

	revGeneral := ReverseIP(ip)
	if revGeneral != expected {
		t.Fatalf("expected %q, got %q", expected, revGeneral)
	}
}

func TestParseIPString(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"192.0.2.1", "192.0.2.1", false},
		{"192.0.2.1:25", "192.0.2.1", false},
		{"[2001:db8::1]:25", "2001:db8::1", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"", "", true},
		{"invalid-ip", "", true},
	}

	for _, tt := range tests {
		ip, err := ParseIPString(tt.input)
		if tt.err && err == nil {
			t.Fatalf("expected error for %q", tt.input)
		}
		if !tt.err && err != nil {
			t.Fatalf("unexpected error for %q: %v", tt.input, err)
		}
		if !tt.err && ip.String() != tt.want {
			t.Fatalf("for %q expected %q, got %q", tt.input, tt.want, ip.String())
		}
	}
}

func TestWhitelisting(t *testing.T) {
	cfg := config.DNSBLConfig{
		Enabled:   true,
		Zones:     []string{"zen.spamhaus.org"},
		Timeout:   1 * time.Second,
		Whitelist: []string{"203.0.113.5", "198.51.100.0/24"},
	}

	checker := New(cfg)

	whitelisted := []string{
		"127.0.0.1",
		"10.0.1.5",
		"172.16.2.3",
		"192.168.1.1",
		"::1",
		"fe80::1",
		"fc00::1",
		"203.0.113.5",
		"198.51.100.42",
	}

	for _, addr := range whitelisted {
		ip, err := ParseIPString(addr)
		if err != nil {
			t.Fatalf("failed to parse %q: %v", addr, err)
		}
		if !checker.IsWhitelisted(ip) {
			t.Fatalf("expected %q to be whitelisted", addr)
		}

		res, err := checker.Check(context.Background(), addr)
		if err != nil {
			t.Fatalf("check failed for whitelisted %q: %v", addr, err)
		}
		if res.Listed {
			t.Fatalf("whitelisted address %q was flagged as listed", addr)
		}
	}

	nonWhitelisted := []string{
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.6",
		"198.51.101.1",
	}

	for _, addr := range nonWhitelisted {
		ip, err := ParseIPString(addr)
		if err != nil {
			t.Fatalf("failed to parse %q: %v", addr, err)
		}
		if checker.IsWhitelisted(ip) {
			t.Fatalf("expected %q NOT to be whitelisted", addr)
		}
	}
}

func TestIsListingCode(t *testing.T) {
	if !isListingCode("127.0.0.2") {
		t.Fatalf("expected 127.0.0.2 to be listing code")
	}
	if !isListingCode("127.0.0.11") {
		t.Fatalf("expected 127.0.0.11 to be listing code")
	}
	if isListingCode("127.255.255.254") {
		t.Fatalf("expected 127.255.255.254 NOT to be listing code")
	}
	if isListingCode("127.255.255.255") {
		t.Fatalf("expected 127.255.255.255 NOT to be listing code")
	}
	if isListingCode("8.8.8.8") {
		t.Fatalf("expected 8.8.8.8 NOT to be listing code")
	}
}

func TestDisabledChecker(t *testing.T) {
	checker := New(config.DNSBLConfig{
		Enabled: false,
		Zones:   []string{"zen.spamhaus.org"},
	})

	res, err := checker.Check(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Listed {
		t.Fatalf("disabled checker should never flag as listed")
	}
}

func TestCheckWithMockDNS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			qnameEnd := 12
			for qnameEnd < n && buf[qnameEnd] != 0 {
				qnameEnd += int(buf[qnameEnd]) + 1
			}
			qnameEnd += 5
			if qnameEnd > n {
				continue
			}

			resp := make([]byte, 0, n+16)
			resp = append(resp, buf[0], buf[1])
			resp = append(resp, 0x81, 0x80)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x00)
			resp = append(resp, 0x00, 0x00)
			resp = append(resp, buf[12:qnameEnd]...)
			resp = append(resp, 0xc0, 0x0c)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x00, 0x01, 0x2c)
			resp = append(resp, 0x00, 0x04)
			resp = append(resp, 127, 0, 0, 2)

			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	mockResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}

	checker := New(config.DNSBLConfig{
		Enabled: true,
		Zones:   []string{"test.dnsbl.local"},
		Timeout: 2 * time.Second,
	}, mockResolver)

	res, err := checker.Check(context.Background(), "198.51.100.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Listed {
		t.Fatalf("expected 198.51.100.2 to be listed in test.dnsbl.local")
	}
	if res.Zone != "test.dnsbl.local" {
		t.Fatalf("expected zone test.dnsbl.local, got %q", res.Zone)
	}
	if res.Record != "127.0.0.2" {
		t.Fatalf("expected record 127.0.0.2, got %q", res.Record)
	}

	detailed, err := checker.CheckDetailed(context.Background(), "198.51.100.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !detailed.Listed || len(detailed.Details) == 0 || !detailed.Details[0].Listed {
		t.Fatalf("expected detailed check to be listed: %+v", detailed)
	}
}
