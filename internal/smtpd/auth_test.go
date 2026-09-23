package smtpd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/arc"
	"github.com/xeron-be/xeron-mx/internal/authres"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type fakeDNS map[string][]string

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[strings.TrimSuffix(strings.ToLower(name), ".")]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (fakeDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (fakeDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func TestIntakeRecordsWhoTheSenderReallyIs(t *testing.T) {
	h := newHarness(t)
	h.srv.SetAuthChecker(&authres.Checker{Resolver: fakeDNS{
		"sender.test": {"v=spf1 ip4:127.0.0.1 -all"},
		"forged.test": {"v=spf1 ip4:192.0.2.1 -all"},
	}})
	domainID := h.addDomain(t, "known.example", true)

	cases := []struct {
		from    string
		results string
		authed  bool
	}{
		{"alice@sender.test", "spf=pass smtp.mailfrom=sender.test; dkim=none; arc=none", true},
		{"ceo@forged.test", "spf=fail smtp.mailfrom=forged.test; dkim=none; arc=none", false},
		{"someone@nowhere.test", "spf=none smtp.mailfrom=nowhere.test; dkim=none; arc=none", false},
	}
	for _, c := range cases {
		if err := h.send(t, c.from, "user@known.example", "Subject: x\r\n\r\nbody\r\n"); err != nil {
			t.Fatalf("send from %s: %v", c.from, err)
		}
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != len(cases) {
		t.Fatalf("%d messages queued; want %d: failing a check must never refuse mail", len(msgs), len(cases))
	}
	byFrom := map[string]*store.Message{}
	for _, m := range msgs {
		byFrom[m.EnvelopeFrom] = m
	}
	for _, c := range cases {
		m := byFrom[c.from]
		if m == nil {
			t.Fatalf("no message from %s", c.from)
		}
		if m.AuthResults != c.results || m.SenderAuthenticated != c.authed {
			t.Errorf("from %s: results %q, authenticated %v; want %q, %v",
				c.from, m.AuthResults, m.SenderAuthenticated, c.results, c.authed)
		}
	}
}

func TestIntakeWithoutAChecker(t *testing.T) {
	h := newHarness(t)
	domainID := h.addDomain(t, "known.example", true)
	if err := h.send(t, "alice@sender.test", "user@known.example", "Subject: x\r\n\r\nbody\r\n"); err != nil {
		t.Fatal(err)
	}
	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("ListMessages = %d, %v", len(msgs), err)
	}
	if msgs[0].AuthResults != "" || msgs[0].SenderAuthenticated {
		t.Fatalf("results %q, authenticated %v; want nothing claimed when nothing was checked",
			msgs[0].AuthResults, msgs[0].SenderAuthenticated)
	}
}

func TestAKnownRecipientListRefusesTheRestAtRcpt(t *testing.T) {
	h := newHarness(t)
	domainID := h.addDomain(t, "known.example", true)
	h.addDomain(t, "open.example", true)
	if err := h.db.SetDomainRecipients(context.Background(), domainID, []string{"alice@known.example"}); err != nil {
		t.Fatal(err)
	}

	if err := h.send(t, "a@sender.test", "Alice@Known.Example", "Subject: x\r\n\r\nbody\r\n"); err != nil {
		t.Fatalf("a listed recipient was refused: %v", err)
	}
	err := h.send(t, "a@sender.test", "nobody@known.example", "Subject: x\r\n\r\nbody\r\n")
	var reply *smtp.SMTPError
	if !errors.As(err, &reply) || reply.Code != 550 || reply.EnhancedCode != (smtp.EnhancedCode{5, 1, 1}) {
		t.Fatalf("unlisted recipient: %v; want 550 5.1.1 at RCPT, so the sender is told at once", err)
	}
	if err := h.send(t, "a@sender.test", "anyone@open.example", "Subject: x\r\n\r\nbody\r\n"); err != nil {
		t.Fatalf("a domain without a list refused mail: %v", err)
	}

	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("%d messages queued; want the two accepted ones", len(msgs))
	}
}

func TestIntakeValidatesAnExistingARCChain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.srv.SetAuthChecker(&authres.Checker{Resolver: fakeDNS{
		"sender.test":                   {"v=spf1 ip4:127.0.0.1 -all"},
		"sel._domainkey.forwarder.test": {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)},
	}})
	domainID := h.addDomain(t, "known.example", true)

	original := "From: alice@sender.test\r\nTo: user@known.example\r\nSubject: forwarded\r\n" +
		"Date: Wed, 23 Sep 2026 15:00:00 +0000\r\n\r\n  indented body\r\n"
	var sealed bytes.Buffer
	if err := arc.NewSealer("forwarder.test", "sel", key).Seal(&sealed, strings.NewReader(original), "mx.forwarder.test", "spf=pass", ""); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(sealed.String(), "indented body", "edited body", 1)

	for _, body := range []string{sealed.String(), tampered} {
		if err := h.send(t, "alice@sender.test", "user@known.example", body); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := h.db.ListMessages(context.Background(), store.ListFilter{DomainID: domainID})
	if err != nil || len(msgs) != 2 {
		t.Fatalf("ListMessages = %d, %v", len(msgs), err)
	}
	var got []string
	for _, m := range msgs {
		got = append(got, authres.ARCResult(m.AuthResults))
	}
	if !(len(got) == 2 && ((got[0] == "pass" && got[1] == "fail") || (got[0] == "fail" && got[1] == "pass"))) {
		t.Fatalf("arc results = %q; want one pass (intact) and one fail (edited)", got)
	}
}
