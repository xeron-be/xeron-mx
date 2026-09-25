package totp

import (
	"bytes"
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"
)

var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

func TestCodeMatchesRFC6238(t *testing.T) {
	vectors := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range vectors {
		got, err := Code(rfcSecret, Step(time.Unix(unix, 0)))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("T=%d: code %s; want %s", unix, got, want)
		}
	}
}

func TestVerifyAcceptsOneStepOfClockDrift(t *testing.T) {
	now := time.Unix(1111111111, 0)
	for _, drift := range []int64{-1, 0, 1} {
		code, _ := Code(rfcSecret, Step(now)+drift)
		if step, ok := Verify(rfcSecret, code, now, 0); !ok || step != Step(now)+drift {
			t.Errorf("drift %d: Verify = %d, %v", drift, step, ok)
		}
	}
	code, _ := Code(rfcSecret, Step(now)+2)
	if _, ok := Verify(rfcSecret, code, now, 0); ok {
		t.Error("a code two steps ahead was accepted")
	}
}

func TestVerifyRefusesAReplayedCode(t *testing.T) {
	now := time.Unix(1234567890, 0)
	code, _ := Code(rfcSecret, Step(now))
	step, ok := Verify(rfcSecret, code, now, 0)
	if !ok {
		t.Fatal("fresh code refused")
	}
	if _, ok := Verify(rfcSecret, code, now, step); ok {
		t.Fatal("the same code was accepted twice")
	}
	older, _ := Code(rfcSecret, Step(now)-1)
	if _, ok := Verify(rfcSecret, older, now, step); ok {
		t.Fatal("an older code was accepted after a newer one")
	}
}

func TestVerifyRefusesMalformedCodes(t *testing.T) {
	now := time.Unix(59, 0)
	for _, c := range []string{"", "28708", "2870821", "abcdef", "28708a", "287 08"} {
		if _, ok := Verify(rfcSecret, c, now, 0); ok {
			t.Errorf("%q accepted", c)
		}
	}
	if _, ok := Verify(rfcSecret, " 287 082 ", now, 0); !ok {
		t.Error("a code typed with spaces was refused")
	}
	if _, ok := Verify("not base32!", "287082", now, 0); ok {
		t.Error("an unreadable secret verified a code")
	}
}

func TestNewSecretIsRandomAndDecodes(t *testing.T) {
	a, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSecret()
	if a == b {
		t.Fatal("two secrets are identical")
	}
	if len(a) != 32 {
		t.Fatalf("secret %q: want 32 base32 characters (160 bits)", a)
	}
	if _, err := Code(a, 1); err != nil {
		t.Fatalf("generated secret does not decode: %v", err)
	}
}

func TestURIIsReadableByAuthenticatorApps(t *testing.T) {
	uri := URI("XeronMX (mx.example.com)", "alice@example.com", rfcSecret)
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("uri %s: want otpauth://totp/", uri)
	}
	if !strings.HasSuffix(u.Path, ":alice@example.com") {
		t.Fatalf("label %q does not end with the account", u.Path)
	}
	q := u.Query()
	if q.Get("secret") != rfcSecret || q.Get("issuer") != "XeronMX (mx.example.com)" ||
		q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" {
		t.Fatalf("query = %v", q)
	}
}

func TestQRCodeIsAPNG(t *testing.T) {
	png, err := QRCodePNG(URI("XeronMX", "alice@example.com", rfcSecret))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("not a PNG")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("%d codes; want %d", len(codes), RecoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("code %q malformed or repeated", c)
		}
		seen[c] = true
		if LooksLikeCode(c) {
			t.Fatalf("recovery code %q could be mistaken for a TOTP code", c)
		}
	}
	if HashRecoveryCode(codes[0]) != HashRecoveryCode(" "+strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))+" ") {
		t.Fatal("a recovery code typed in capitals without the dash hashes differently")
	}
	if HashRecoveryCode(codes[0]) == HashRecoveryCode(codes[1]) {
		t.Fatal("two codes share a hash")
	}
}
