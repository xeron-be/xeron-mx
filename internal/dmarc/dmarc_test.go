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

func TestBuildValue(t *testing.T) {
	cfg := DMARCConfig{
		Policy:          "quarantine",
		SubdomainPolicy: "reject",
		RUA:             "mailto:reports@example.com",
		Percent:         100,
		DKIMAlignment:   "r",
		SPFAlignment:    "r",
	}

	val := BuildValue(cfg, "example.com")
	expectedParts := []string{
		"v=DMARC1",
		"p=quarantine",
		"sp=reject",
		"rua=mailto:reports@example.com",
		"pct=100",
		"adkim=r",
		"aspf=r",
	}

	for _, p := range expectedParts {
		if !contains(val, p) {
			t.Errorf("BuildValue missing part %q, got: %s", p, val)
		}
	}
}

func TestDefaultValue(t *testing.T) {
	val := DefaultValue("example.com", "quarantine")
	if val != "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@example.com; pct=100" {
		t.Errorf("unexpected DefaultValue: %s", val)
	}
}

func TestCheckAlignment(t *testing.T) {
	cases := []struct {
		from   string
		auth   string
		strict bool
		want   bool
	}{
		{"example.com", "example.com", true, true},
		{"example.com", "example.com", false, true},
		{"sub.example.com", "example.com", true, false},
		{"sub.example.com", "example.com", false, true},
		{"mail.corp.example.co.uk", "example.co.uk", false, true},
		{"mail.corp.example.co.uk", "example.co.uk", true, false},
		{"different.org", "example.com", false, false},
		{"", "example.com", false, false},
		{"example.com", "", false, false},
	}

	for _, tc := range cases {
		got := CheckAlignment(tc.from, tc.auth, tc.strict)
		if got != tc.want {
			t.Errorf("CheckAlignment(%q, %q, %v) = %v, want %v", tc.from, tc.auth, tc.strict, got, tc.want)
		}
	}
}

func TestOrgDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"mail.example.co.uk", "example.co.uk"},
		{"sub.mail.example.asso.fr", "example.asso.fr"},
	}

	for _, tc := range cases {
		got := OrgDomain(tc.in)
		if got != tc.want {
			t.Errorf("OrgDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && hasSubstr(s, substr)))
}

func hasSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
