package dmarc

import (
	"context"
	"testing"
	"time"
)

func TestRecordName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "_dmarc.example.com."},
		{"example.com.", "_dmarc.example.com."},
		{"sub.example.com", "_dmarc.sub.example.com."},
	}

	for _, tc := range cases {
		got := RecordName(tc.in)
		if got != tc.want {
			t.Errorf("RecordName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDefaultValue(t *testing.T) {
	val := DefaultValue("example.com", "quarantine")
	if val != "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@example.com; pct=100" {
		t.Errorf("unexpected DefaultValue: %s", val)
	}
}

func TestCheckDNSLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	res, err := CheckDNS(ctx, "google.com")
	if err != nil {
		t.Fatalf("CheckDNS error: %v", err)
	}
	if !res.Found {
		t.Skip("network unavailable or google.com TXT not returned via DoH")
	}
	if !res.Valid {
		t.Errorf("google.com DMARC record should be valid, got error: %s", res.Error)
	}
	if res.Policy == "" {
		t.Errorf("google.com should have a non-empty DMARC policy")
	}
}
