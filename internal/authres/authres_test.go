package authres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

type fakeDNS struct {
	txt   map[string][]string
	delay time.Duration
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, IsTemporary: true}
		}
	}
	if v, ok := f.txt[strings.TrimSuffix(strings.ToLower(name), ".")]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (f *fakeDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (f *fakeDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

const message = "From: alice@sender.test\r\n" +
	"To: bob@example.test\r\n" +
	"Subject: signed\r\n" +
	"\r\n" +
	"Hello.\r\n"

func signedBy(t *testing.T, dns *fakeDNS, domain string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dns.txt["sel._domainkey."+domain] = []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)}

	var out bytes.Buffer
	err = dkim.Sign(&out, strings.NewReader(message), &dkim.SignOptions{
		Domain: domain, Selector: "sel", Signer: key,
		HeaderKeys: []string{"From", "To", "Subject"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestSPF(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{
		"sender.test":     {"v=spf1 ip4:192.0.2.1 -all"},
		"mail.relay.test": {"v=spf1 ip4:192.0.2.9 -all"},
	}}
	c := &Checker{Resolver: dns}
	ctx := context.Background()

	cases := []struct {
		name     string
		ip       string
		helo     string
		from     string
		result   string
		domain   string
		heloUsed bool
	}{
		{"authorised", "192.0.2.1", "mx.sender.test", "alice@sender.test", "pass", "sender.test", false},
		{"not authorised", "198.51.100.7", "mx.sender.test", "alice@sender.test", "fail", "sender.test", false},
		{"no record", "192.0.2.1", "mx.other.test", "alice@other.test", "none", "other.test", false},
		{"null sender checks the helo", "192.0.2.9", "mail.relay.test", "", "pass", "mail.relay.test", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := c.SPF(ctx, net.ParseIP(tc.ip), tc.helo, tc.from)
			if r.SPF != tc.result || r.SPFDomain != tc.domain || r.SPFHelo != tc.heloUsed {
				t.Fatalf("SPF = %s for %s (helo %v); want %s for %s (helo %v)",
					r.SPF, r.SPFDomain, r.SPFHelo, tc.result, tc.domain, tc.heloUsed)
			}
		})
	}
}

func TestSPFGivesUpAtTheTimeout(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{"sender.test": {"v=spf1 -all"}}, delay: time.Minute}
	c := &Checker{Resolver: dns, Timeout: 200 * time.Millisecond}

	start := time.Now()
	r := c.SPF(context.Background(), net.ParseIP("192.0.2.1"), "mx.sender.test", "alice@sender.test")
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("SPF took %v; want it bounded by the 200ms timeout", elapsed)
	}
	if r.SPF != "temperror" {
		t.Fatalf("SPF = %s; want temperror when DNS does not answer in time", r.SPF)
	}
}

func TestDKIM(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{}}
	c := &Checker{Resolver: dns}
	ctx := context.Background()
	signed := signedBy(t, dns, "sender.test")

	if got := c.DKIM(ctx, strings.NewReader(signed)); len(got) != 1 || got[0] != (Signature{"sender.test", "pass"}) {
		t.Fatalf("intact message: %+v; want one pass for sender.test", got)
	}
	tampered := strings.Replace(signed, "Hello.", "Hello!", 1)
	if got := c.DKIM(ctx, strings.NewReader(tampered)); len(got) != 1 || got[0].Result != "fail" {
		t.Fatalf("tampered message: %+v; want fail", got)
	}
	if got := c.DKIM(ctx, strings.NewReader(message)); len(got) != 0 {
		t.Fatalf("unsigned message: %+v; want no signatures", got)
	}
	delete(dns.txt, "sel._domainkey.sender.test")
	if got := c.DKIM(ctx, strings.NewReader(signed)); len(got) != 1 || got[0].Result == "pass" {
		t.Fatalf("key withdrawn: %+v; want the signature not to pass", got)
	}
}

type countingReader struct {
	r    *strings.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func TestDKIMAlwaysDrainsItsInput(t *testing.T) {
	c := &Checker{Resolver: &fakeDNS{txt: map[string][]string{}}}
	garbage := "this is not a message header at all\r\n" + strings.Repeat("x", 100000)
	r := &countingReader{r: strings.NewReader(garbage)}

	c.DKIM(context.Background(), r)

	if r.read != len(garbage) {
		t.Fatalf("read %d of %d bytes; a writer feeding the verifier through a pipe would block", r.read, len(garbage))
	}
}

func TestHeader(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want string
	}{
		{"nothing checked", Result{}, ""},
		{"spf only", Result{SPF: "pass", SPFDomain: "sender.test"}, "spf=pass smtp.mailfrom=sender.test; dkim=none"},
		{"helo identity", Result{SPF: "none", SPFDomain: "mx.relay.test", SPFHelo: true}, "spf=none smtp.helo=mx.relay.test; dkim=none"},
		{"signatures", Result{SPF: "fail", SPFDomain: "sender.test", DKIM: []Signature{{"sender.test", "pass"}, {"list.test", "fail"}}},
			"spf=fail smtp.mailfrom=sender.test; dkim=pass header.d=sender.test; dkim=fail header.d=list.test"},
		{"hostile domain", Result{SPF: "pass", SPFDomain: "evil.test", DKIM: []Signature{{"a.test;\r\nX-Injected: yes", "pass"}}},
			"spf=pass smtp.mailfrom=evil.test; dkim=pass header.d=a.testX-Injectedyes"},
		{"arc", Result{SPF: "pass", SPFDomain: "gmail.com", DKIM: []Signature{{"gmail.com", "pass"}}, ARC: "pass"},
			"spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; arc=pass"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Header(); got != tc.want {
				t.Fatalf("Header() = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestAuthenticates(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		from string
		want bool
	}{
		{"spf pass for the envelope domain", Result{SPF: "pass", SPFDomain: "sender.test"}, "alice@sender.test", true},
		{"spf softfail", Result{SPF: "softfail", SPFDomain: "sender.test"}, "alice@sender.test", false},
		{"spf pass for the helo only", Result{SPF: "pass", SPFDomain: "sender.test", SPFHelo: true}, "alice@sender.test", false},
		{"null sender", Result{SPF: "pass", SPFDomain: "relay.test", SPFHelo: true}, "", false},
		{"aligned dkim", Result{SPF: "fail", DKIM: []Signature{{"mail.sender.test", "pass"}}}, "alice@bounces.sender.test", true},
		{"dkim from another domain", Result{SPF: "fail", DKIM: []Signature{{"list.test", "pass"}}}, "alice@sender.test", false},
		{"failing aligned dkim", Result{DKIM: []Signature{{"sender.test", "fail"}}}, "alice@sender.test", false},
		{"public suffix is not an organisation", Result{DKIM: []Signature{{"co.uk", "pass"}}}, "alice@victim.co.uk", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Authenticates(tc.from); got != tc.want {
				t.Fatalf("Authenticates(%q) = %v; want %v", tc.from, got, tc.want)
			}
		})
	}
}

func TestARCResult(t *testing.T) {
	for header, want := range map[string]string{
		"spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; arc=pass": "pass",
		"spf=fail smtp.mailfrom=list.test; dkim=none; ARC=Fail":                    "fail",
		"spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com":           "",
		"": "",
	} {
		if got := ARCResult(header); got != want {
			t.Errorf("ARCResult(%q) = %q, want %q", header, got, want)
		}
	}
}
