package arc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeDNS map[string]string

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return []string{v}, nil
	}
	return nil, errors.New("no such record")
}

func rsaKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func edKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)
}

const message = "From: Sender <sender@origin.example>\r\n" +
	"To: rcpt@dest.example\r\n" +
	"Subject: an ARC test\r\n" +
	"Date: Wed, 23 Sep 2026 15:00:00 +0000\r\n" +
	"Message-ID: <arc-test@origin.example>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"\r\n" +
	"first line\r\n" +
	"    an indented   line with  runs\r\n" +
	"\ta tab-indented line   \r\n" +
	"\r\n\r\n"

func seal(t *testing.T, signer crypto.Signer, domain, msg, results, cv string) string {
	t.Helper()
	var out bytes.Buffer
	if err := NewSealer(domain, "sel", signer).Seal(&out, strings.NewReader(msg), "mx."+domain, results, cv); err != nil {
		t.Fatalf("Seal(%s): %v", domain, err)
	}
	return out.String()
}

func TestSealVerifiesWithBothKeyTypes(t *testing.T) {
	rk, rrec := rsaKey(t)
	ek, erec := edKey(t)
	for name, c := range map[string]struct {
		signer crypto.Signer
		record string
		algo   string
	}{
		"rsa":     {rk, rrec, "a=rsa-sha256"},
		"ed25519": {ek, erec, "a=ed25519-sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			sealed := seal(t, c.signer, "hop1.example", message, "spf=pass smtp.mailfrom=origin.example", "")
			if !strings.Contains(sealed, c.algo) || !strings.Contains(sealed, "cv=none") {
				t.Fatalf("sealed headers = %q", sealed[:strings.Index(sealed, "From:")])
			}
			res := Verify(context.Background(), []byte(sealed), fakeDNS{"sel._domainkey.hop1.example": c.record})
			if res.CV != CVPass || res.Instance != 1 {
				t.Fatalf("Verify = %+v; want pass at instance 1", res)
			}
		})
	}
}

func TestSealedHeadersComeFirstInSetOrder(t *testing.T) {
	k, _ := rsaKey(t)
	sealed := seal(t, k, "hop1.example", message, "spf=pass", "")
	as := strings.Index(sealed, "ARC-Seal: i=1;")
	ams := strings.Index(sealed, "ARC-Message-Signature: i=1;")
	aar := strings.Index(sealed, "ARC-Authentication-Results: i=1; mx.hop1.example; spf=pass")
	from := strings.Index(sealed, "From: Sender")
	if as != 0 || !(as < ams && ams < aar && aar < from) {
		t.Fatalf("header order AS=%d AMS=%d AAR=%d From=%d", as, ams, aar, from)
	}
	if !strings.HasSuffix(sealed, message) {
		t.Fatal("the original message was not carried unchanged after the new set")
	}
}

func TestEmptyResultsAreRecordedAsNone(t *testing.T) {
	k, _ := rsaKey(t)
	sealed := seal(t, k, "hop1.example", message, "", "")
	if !strings.Contains(sealed, "ARC-Authentication-Results: i=1; mx.hop1.example; none\r\n") {
		t.Fatalf("AAR = %q", sealed)
	}
}

func TestIndentedBodyLinesSurviveRelaxedCanonicalization(t *testing.T) {
	got := string(canonBody([]byte("a\r\n    b  c \r\n\tx\t\r\n\r\n\r\n"), true))
	if want := "a\r\n b c\r\n x\r\n"; got != want {
		t.Fatalf("relaxed body = %q, want %q", got, want)
	}
	if got := string(canonBody(nil, true)); got != "" {
		t.Fatalf("relaxed empty body = %q", got)
	}
	if got := string(canonBody([]byte("a  \r\n\r\n"), false)); got != "a  \r\n" {
		t.Fatalf("simple body = %q", got)
	}
	if got := string(canonBody(nil, false)); got != "\r\n" {
		t.Fatalf("simple empty body = %q", got)
	}
}

func TestSecondHopExtendsAValidatedChain(t *testing.T) {
	k1, rec1 := rsaKey(t)
	k2, rec2 := edKey(t)
	dns := fakeDNS{"sel._domainkey.hop1.example": rec1, "sel._domainkey.hop2.example": rec2}

	hop1 := seal(t, k1, "hop1.example", message, "spf=pass", "")
	if res := Verify(context.Background(), []byte(hop1), dns); res.CV != CVPass {
		t.Fatalf("hop1 = %+v", res)
	}
	hop2 := seal(t, k2, "hop2.example", hop1, "arc=pass; spf=fail", CVPass)
	if !strings.Contains(hop2, "ARC-Seal: i=2; a=ed25519-sha256; cv=pass;") {
		t.Fatalf("second seal = %q", hop2[:200])
	}
	if res := Verify(context.Background(), []byte(hop2), dns); res.CV != CVPass || res.Instance != 2 {
		t.Fatalf("Verify(hop2) = %+v; want pass at instance 2", res)
	}
}

func TestSealRefusesToExtendAChainItCannotVouchFor(t *testing.T) {
	k, _ := rsaKey(t)
	hop1 := seal(t, k, "hop1.example", message, "spf=pass", "")

	for _, cv := range []string{"", CVNone} {
		var out bytes.Buffer
		err := NewSealer("hop2.example", "sel", k).Seal(&out, strings.NewReader(hop1), "mx.hop2.example", "spf=pass", cv)
		if !errors.Is(err, ErrUnvalidatedChain) || out.Len() != 0 {
			t.Fatalf("Seal over a chain with cv=%q = %v, wrote %d bytes; want ErrUnvalidatedChain and nothing", cv, err, out.Len())
		}
	}

	failed := seal(t, k, "hop2.example", hop1, "arc=fail", CVFail)
	if !strings.Contains(failed, "ARC-Seal: i=2; a=rsa-sha256; cv=fail;") {
		t.Fatal("a chain that failed validation is sealed with cv=fail")
	}
	var out bytes.Buffer
	err := NewSealer("hop3.example", "sel", k).Seal(&out, strings.NewReader(failed), "mx.hop3.example", "arc=fail", CVFail)
	if !errors.Is(err, ErrFailedChain) {
		t.Fatalf("Seal over a failed chain = %v; want ErrFailedChain", err)
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	k, rec := rsaKey(t)
	dns := fakeDNS{"sel._domainkey.hop1.example": rec}
	sealed := seal(t, k, "hop1.example", message, "spf=pass", "")

	for name, c := range map[string]struct{ from, to, reason string }{
		"body":    {"first line", "first line, edited", "body hash"},
		"subject": {"Subject: an ARC test", "Subject: an edited test", "signature does not verify"},
		"aar":     {"mx.hop1.example; spf=pass", "mx.hop1.example; spf=fail", "arc-seal 1"},
	} {
		t.Run(name, func(t *testing.T) {
			res := Verify(context.Background(), []byte(strings.Replace(sealed, c.from, c.to, 1)), dns)
			if res.CV != CVFail || !strings.Contains(res.Reason, c.reason) {
				t.Fatalf("Verify = %+v; want fail mentioning %q", res, c.reason)
			}
		})
	}

	if res := Verify(context.Background(), []byte(sealed), fakeDNS{}); res.CV != CVFail {
		t.Fatalf("Verify without the key = %+v; want fail", res)
	}
}

func TestVerifyStructure(t *testing.T) {
	k, rec := rsaKey(t)
	dns := fakeDNS{"sel._domainkey.hop1.example": rec}
	sealed := seal(t, k, "hop1.example", message, "spf=pass", "")

	if res := Verify(context.Background(), []byte(message), dns); res.CV != CVNone {
		t.Fatalf("no chain: %+v", res)
	}
	noAAR := strings.Replace(sealed, "ARC-Authentication-Results: i=1;", "X-Removed: i=1;", 1)
	if res := Verify(context.Background(), []byte(noAAR), dns); res.CV != CVFail || !strings.Contains(res.Reason, "incomplete") {
		t.Fatalf("incomplete set: %+v", res)
	}
	wrongCV := strings.Replace(sealed, "cv=none", "cv=pass", 1)
	if res := Verify(context.Background(), []byte(wrongCV), dns); res.CV != CVFail || !strings.Contains(res.Reason, "cv=pass") {
		t.Fatalf("cv=pass at instance 1: %+v", res)
	}
	gap := strings.NewReplacer("ARC-Seal: i=1;", "ARC-Seal: i=2;",
		"ARC-Message-Signature: i=1;", "ARC-Message-Signature: i=2;",
		"ARC-Authentication-Results: i=1;", "ARC-Authentication-Results: i=2;").Replace(sealed)
	if res := Verify(context.Background(), []byte(gap), dns); res.CV != CVFail {
		t.Fatalf("chain starting at i=2: %+v", res)
	}
}

func TestVerifiesAChainSealedByDkimpy(t *testing.T) {
	msg, err := os.ReadFile("testdata/dkimpy-two-hops.eml")
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile("testdata/dkimpy-two-hops.dns.txt")
	if err != nil {
		t.Fatal(err)
	}
	dns := fakeDNS{
		"sel._domainkey.hop1.example": string(key),
		"sel._domainkey.hop2.example": string(key),
	}
	if res := Verify(context.Background(), msg, dns); res.CV != CVPass || res.Instance != 2 {
		t.Fatalf("Verify(dkimpy chain) = %+v; want pass at instance 2", res)
	}

	lf := bytes.ReplaceAll(msg, []byte("\r\n"), []byte("\n"))
	if res := Verify(context.Background(), lf, dns); res.CV != CVPass {
		t.Fatalf("Verify(dkimpy chain with LF line endings) = %+v", res)
	}

	tampered := bytes.Replace(msg, []byte("an indented"), []byte("an altered"), 1)
	if res := Verify(context.Background(), tampered, dns); res.CV != CVFail {
		t.Fatalf("Verify(tampered dkimpy chain) = %+v; want fail", res)
	}

	k, rec := rsaKey(t)
	dns["sel._domainkey.hop3.example"] = rec
	hop3 := seal(t, k, "hop3.example", string(msg), "arc=pass", CVPass)
	if res := Verify(context.Background(), []byte(hop3), dns); res.CV != CVPass || res.Instance != 3 {
		t.Fatalf("Verify(dkimpy chain + our seal) = %+v; want pass at instance 3", res)
	}
}

func TestSealTimestampComesFromTheClock(t *testing.T) {
	k, _ := rsaKey(t)
	s := NewSealer("hop1.example", "sel", k)
	s.Now = func() time.Time { return time.Unix(1790175600, 0) }
	var out bytes.Buffer
	if err := s.Seal(&out, strings.NewReader(message), "mx.hop1.example", "", ""); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "t=1790175600;") != 2 {
		t.Fatalf("seal = %q", out.String()[:300])
	}
}
