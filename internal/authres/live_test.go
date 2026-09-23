package authres

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func requireLiveDNS(t *testing.T) {
	t.Helper()
	if os.Getenv("XERONMX_LIVE_DNS") == "" {
		t.Skip("set XERONMX_LIVE_DNS=1 to run against the public DNS")
	}
}

func TestLiveSPF(t *testing.T) {
	requireLiveDNS(t)
	c := &Checker{}
	ctx := context.Background()

	cases := []struct {
		name string
		ip   string
		from string
		want []string
	}{
		{"a domain that sends no mail", "192.0.2.1", "someone@example.com", []string{"fail"}},
		{"gmail from google, through a redirect", "209.85.220.41", "someone@gmail.com", []string{"pass"}},
		{"gmail from google over ipv6", "2a00:1450:4864::1", "someone@gmail.com", []string{"pass"}},
		{"gmail from anywhere else", "192.0.2.1", "someone@gmail.com", []string{"softfail"}},
		{"github from its own block", "192.30.252.1", "noreply@github.com", []string{"pass"}},
		{"github from anywhere else, after every include", "192.0.2.1", "noreply@github.com", []string{"softfail", "permerror"}},
		{"a domain that does not exist", "192.0.2.1", "someone@does-not-exist.invalid", []string{"none"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			r := c.SPF(ctx, net.ParseIP(tc.ip), "client.example", tc.from)
			t.Logf("%s from %s: spf=%s in %v", tc.from, tc.ip, r.SPF, time.Since(start).Round(time.Millisecond))
			if !slices.Contains(tc.want, r.SPF) {
				t.Fatalf("spf=%s; want one of %v", r.SPF, tc.want)
			}
		})
	}
}

func TestLiveDKIM(t *testing.T) {
	requireLiveDNS(t)
	dir := os.Getenv("XERONMX_LIVE_EML")
	if dir == "" {
		t.Skip("set XERONMX_LIVE_EML to a directory of real .eml files")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.eml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no .eml files in %s", dir)
	}
	c := &Checker{}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			sigs := c.DKIM(context.Background(), strings.NewReader(string(raw)))
			t.Logf("%+v", sigs)
			if len(sigs) == 0 {
				t.Fatal("no DKIM signature found")
			}
			if !slices.ContainsFunc(sigs, func(s Signature) bool { return s.Result == "pass" }) {
				t.Fatalf("no signature passed: %+v", sigs)
			}
		})
	}
}
