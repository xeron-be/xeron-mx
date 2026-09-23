package dkim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const sample = "From: sender@example.test\r\n" +
	"To: recipient@elsewhere.test\r\n" +
	"Subject: A test message\r\n" +
	"Date: Mon, 24 Aug 2026 12:00:00 +0000\r\n" +
	"Message-ID: <abc@example.test>\r\n" +
	"\r\n" +
	"The body of the message.\r\n"

func TestGenerateRSAProducesAUsableKeypair(t *testing.T) {
	k, err := Generate("mail", store.AlgorithmRSA)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k.Algorithm != store.AlgorithmRSA || k.Selector != "mail" {
		t.Fatalf("key metadata is wrong: %+v", k)
	}

	block, _ := pem.Decode(k.PrivatePEM)
	if block == nil {
		t.Fatal("the private key is not valid PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("the private key does not parse: %v", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected an RSA key, got %T", priv)
	}
	if bits := rsaKey.N.BitLen(); bits < 2048 {
		t.Fatalf("key is %d bits; below 2048 some receivers treat the mail as unsigned", bits)
	}

	der, err := base64.StdEncoding.DecodeString(k.PublicB64)
	if err != nil {
		t.Fatalf("the public key is not base64: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("the public key does not parse: %v", err)
	}
	if !rsaKey.PublicKey.Equal(pub) {
		t.Fatal("the published public key does not match the private key: nothing would ever verify")
	}
}

func TestGenerateEd25519(t *testing.T) {
	k, err := Generate("mail", store.AlgorithmEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	block, _ := pem.Decode(k.PrivatePEM)
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	edKey, ok := priv.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected an ed25519 key, got %T", priv)
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(edKey.Public().(ed25519.PublicKey), ed25519.PublicKey(pub)) {
		t.Fatal("the published public key does not match the private key")
	}
}

func TestGenerateDefaultsToRSA(t *testing.T) {
	k, err := Generate("", "")
	if err != nil {
		t.Fatal(err)
	}
	if k.Algorithm != store.AlgorithmRSA {
		t.Errorf("algorithm = %q, want rsa", k.Algorithm)
	}
	if k.Selector != DefaultSelector {
		t.Errorf("selector = %q, want %q", k.Selector, DefaultSelector)
	}
}

func TestGenerateRejectsBadInput(t *testing.T) {
	if _, err := Generate("has spaces", store.AlgorithmRSA); err == nil {
		t.Error("a selector with a space was accepted; it would not be a valid DNS label")
	}
	if _, err := Generate("mail", "dsa"); err == nil {
		t.Error("an unknown algorithm was accepted")
	}
}

func TestSignAddsAVerifiableSignature(t *testing.T) {
	k, err := Generate("mail", store.AlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("example.test", k.Selector, k.PrivatePEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	var out bytes.Buffer
	if err := signer.Sign(&out, strings.NewReader(sample)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed := out.String()

	if !strings.Contains(signed, "DKIM-Signature:") {
		t.Fatal("no DKIM-Signature header was added")
	}
	for _, want := range []string{"d=example.test", "s=mail", "a=rsa-sha256", "c=relaxed/relaxed"} {
		if !strings.Contains(signed, want) {
			t.Errorf("the signature does not carry %s:\n%s", want, firstHeader(signed))
		}
	}
	if !strings.Contains(signed, "The body of the message.") {
		t.Fatal("the body did not survive signing")
	}
	if !strings.Contains(signed, "Subject: A test message") {
		t.Fatal("the original headers did not survive signing")
	}
}

func TestSignedHeadersCoverFrom(t *testing.T) {
	found := false
	for _, h := range SignedHeaders {
		if strings.EqualFold(h, "From") {
			found = true
		}
	}
	if !found {
		t.Fatal("From is not in the signed header set")
	}
	for _, h := range SignedHeaders {
		if strings.HasPrefix(strings.ToLower(h), "x-spam") {
			t.Errorf("%s is signed, but this daemon adds it at delivery: the signature would break", h)
		}
	}
}

func TestSignRejectsAKeyItCannotParse(t *testing.T) {
	if _, err := NewSigner("example.test", "mail", []byte("not pem at all")); err == nil {
		t.Fatal("NewSigner accepted something that is not a key")
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	if _, err := NewSigner("example.test", "mail", bad); err == nil {
		t.Fatal("NewSigner accepted a PEM block that is not a key")
	}
}

func TestDNSRecord(t *testing.T) {
	k, err := Generate("s1", store.AlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}

	if got := RecordName("s1", "example.test"); got != "s1._domainkey.example.test." {
		t.Errorf("record name = %q", got)
	}
	value := RecordValue(k.Algorithm, k.PublicB64)
	if !strings.HasPrefix(value, "v=DKIM1; k=rsa; p=") {
		t.Errorf("record value = %q", value)
	}
	if !strings.Contains(value, k.PublicB64) {
		t.Error("the record does not carry the public key")
	}

	ed, err := Generate("s2", store.AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(RecordValue(ed.Algorithm, ed.PublicB64), "k=ed25519") {
		t.Error("an ed25519 record does not declare its key type")
	}
}

func firstHeader(msg string) string {
	if i := strings.Index(msg, "\r\n\r\n"); i > 0 {
		return msg[:i]
	}
	return msg
}

func TestTheSignatureCoversWhatAReplayCouldChange(t *testing.T) {
	key, err := Generate("sel", "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("example.com", "sel", key.PrivatePEM)
	if err != nil {
		t.Fatal(err)
	}
	msg := "From: a@example.com\r\nTo: b@example.net\r\nSubject: hi\r\n" +
		"Content-Type: text/plain\r\n\r\nbody\r\n"
	var out bytes.Buffer
	if err := signer.Sign(&out, strings.NewReader(msg)); err != nil {
		t.Fatal(err)
	}
	head := out.String()[:strings.Index(out.String(), "From: a@example.com")]
	h := strings.ToLower(strings.Join(strings.Fields(head), ""))
	for _, name := range []string{"reply-to", "cc", "content-type", "content-transfer-encoding", "message-id"} {
		if !strings.Contains(h, name) {
			t.Errorf("the signature does not cover %s, so a replay could add or change it", name)
		}
	}
}
