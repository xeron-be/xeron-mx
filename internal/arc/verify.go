package arc

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	MaxInstances = 50

	CVNone = "none"
	CVPass = "pass"
	CVFail = "fail"

	aarName = "ARC-Authentication-Results"
	amsName = "ARC-Message-Signature"
	asName  = "ARC-Seal"

	minRSABits = 1024
)

type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type Result struct {
	CV       string
	Instance int
	Reason   string
}

type set struct {
	aar, ams, as *field
}

type chain struct {
	sets []set
}

func collect(fields []field) (*chain, error) {
	byInstance := map[int]*set{}
	max := 0
	for i := range fields {
		f := &fields[i]
		var slot func(*set) **field
		switch {
		case strings.EqualFold(f.name, aarName):
			slot = func(s *set) **field { return &s.aar }
		case strings.EqualFold(f.name, amsName):
			slot = func(s *set) **field { return &s.ams }
		case strings.EqualFold(f.name, asName):
			slot = func(s *set) **field { return &s.as }
		default:
			continue
		}
		n, ok := instanceOf(*f)
		if !ok {
			return nil, fmt.Errorf("%s with a missing or invalid instance", f.name)
		}
		s := byInstance[n]
		if s == nil {
			s = &set{}
			byInstance[n] = s
		}
		p := slot(s)
		if *p != nil {
			return nil, fmt.Errorf("two %s headers for instance %d", f.name, n)
		}
		*p = f
		if n > max {
			max = n
		}
	}
	c := &chain{}
	for i := 1; i <= max; i++ {
		s := byInstance[i]
		if s == nil || s.aar == nil || s.ams == nil || s.as == nil {
			return nil, fmt.Errorf("arc set %d is incomplete", i)
		}
		c.sets = append(c.sets, *s)
	}
	return c, nil
}

func (c *chain) latestCV() string {
	if len(c.sets) == 0 {
		return ""
	}
	tags, _ := parseTags(c.sets[len(c.sets)-1].as.value())
	return strings.ToLower(tags["cv"])
}

func Verify(ctx context.Context, raw []byte, resolver TXTResolver) Result {
	raw = normalizeLineEndings(raw)
	fields, body := splitMessage(raw)
	c, err := collect(fields)
	if err != nil {
		return Result{CV: CVFail, Reason: err.Error()}
	}
	n := len(c.sets)
	if n == 0 {
		return Result{CV: CVNone}
	}
	fail := func(format string, args ...any) Result {
		return Result{CV: CVFail, Instance: n, Reason: fmt.Sprintf(format, args...)}
	}

	if c.latestCV() == CVFail {
		return fail("the chain was already marked failed at instance %d", n)
	}
	for i, s := range c.sets {
		tags, ok := parseTags(s.as.value())
		if !ok {
			return fail("arc-seal %d does not parse", i+1)
		}
		want := CVPass
		if i == 0 {
			want = CVNone
		}
		if strings.ToLower(tags["cv"]) != want {
			return fail("arc-seal %d has cv=%s, want %s", i+1, tags["cv"], want)
		}
	}

	if err := verifyAMS(ctx, fields, body, *c.sets[n-1].ams, resolver); err != nil {
		return fail("arc-message-signature %d: %v", n, err)
	}
	for i := n; i >= 1; i-- {
		if err := verifySeal(ctx, c, i, resolver); err != nil {
			return fail("arc-seal %d: %v", i, err)
		}
	}
	return Result{CV: CVPass, Instance: n}
}

func verifyAMS(ctx context.Context, fields []field, body []byte, ams field, resolver TXTResolver) error {
	tags, ok := parseTags(ams.value())
	if !ok {
		return errors.New("tags do not parse")
	}
	for _, t := range []string{"a", "b", "bh", "d", "s", "h"} {
		if tags[t] == "" {
			return fmt.Errorf("missing %s=", t)
		}
	}

	headerRelaxed, bodyRelaxed, err := canonicalization(tags["c"])
	if err != nil {
		return err
	}

	cbody := canonBody(body, bodyRelaxed)
	if l := tags["l"]; l != "" {
		n, err := strconv.ParseInt(l, 10, 64)
		if err != nil || n < 0 {
			return errors.New("invalid l=")
		}
		if n < int64(len(cbody)) {
			cbody = cbody[:n]
		}
	}
	bh := sha256.Sum256(cbody)
	if base64.StdEncoding.EncodeToString(bh[:]) != tags.compact("bh") {
		return errors.New("body hash does not match")
	}

	var input strings.Builder
	used := map[int]bool{}
	for _, name := range strings.Split(tags.compact("h"), ":") {
		for i := len(fields) - 1; i >= 0; i-- {
			if used[i] || !strings.EqualFold(fields[i].name, name) {
				continue
			}
			used[i] = true
			input.WriteString(canonHeader(fields[i], headerRelaxed))
			break
		}
	}
	input.WriteString(strings.TrimSuffix(canonHeader(stripSignature(ams), headerRelaxed), "\r\n"))

	return checkSignature(ctx, tags, []byte(input.String()), resolver)
}

func verifySeal(ctx context.Context, c *chain, instance int, resolver TXTResolver) error {
	s := c.sets[instance-1]
	tags, ok := parseTags(s.as.value())
	if !ok {
		return errors.New("tags do not parse")
	}
	for _, t := range []string{"a", "b", "d", "s"} {
		if tags[t] == "" {
			return fmt.Errorf("missing %s=", t)
		}
	}
	if tags["h"] != "" {
		return errors.New("h= is not allowed in an arc-seal")
	}
	return checkSignature(ctx, tags, sealInput(c.sets[:instance], nil), resolver)
}

func sealInput(sets []set, pending *set) []byte {
	var b strings.Builder
	all := sets
	if pending != nil {
		all = append(append([]set{}, sets...), *pending)
	}
	for i, s := range all {
		b.WriteString(canonHeader(*s.aar, true))
		b.WriteString(canonHeader(*s.ams, true))
		if i == len(all)-1 {
			b.WriteString(strings.TrimSuffix(canonHeader(stripSignature(*s.as), true), "\r\n"))
		} else {
			b.WriteString(canonHeader(*s.as, true))
		}
	}
	return []byte(b.String())
}

func canonicalization(c string) (headerRelaxed, bodyRelaxed bool, err error) {
	if c == "" {
		return false, false, nil
	}
	h, b, _ := strings.Cut(strings.ToLower(c), "/")
	if b == "" {
		b = "simple"
	}
	for _, v := range []string{h, b} {
		if v != "simple" && v != "relaxed" {
			return false, false, fmt.Errorf("unknown canonicalization %q", c)
		}
	}
	return h == "relaxed", b == "relaxed", nil
}

func checkSignature(ctx context.Context, tags tagList, input []byte, resolver TXTResolver) error {
	sig, err := base64.StdEncoding.DecodeString(tags.compact("b"))
	if err != nil {
		return errors.New("b= is not base64")
	}
	key, err := lookupKey(ctx, resolver, tags["s"], tags["d"])
	if err != nil {
		return err
	}
	hash := sha256.Sum256(input)
	switch strings.ToLower(tags["a"]) {
	case "rsa-sha256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("a=rsa-sha256 but the published key is not rsa")
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig) != nil {
			return errors.New("signature does not verify")
		}
	case "ed25519-sha256":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return errors.New("a=ed25519-sha256 but the published key is not ed25519")
		}
		if !ed25519.Verify(pub, hash[:], sig) {
			return errors.New("signature does not verify")
		}
	default:
		return fmt.Errorf("unsupported algorithm %q", tags["a"])
	}
	return nil
}

func lookupKey(ctx context.Context, resolver TXTResolver, selector, domain string) (crypto.PublicKey, error) {
	name := selector + "._domainkey." + strings.TrimSuffix(domain, ".")
	txts, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("key lookup %s: %w", name, err)
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("no key at %s", name)
	}
	tags, ok := parseTags(strings.Join(txts, ""))
	if !ok {
		return nil, fmt.Errorf("key record at %s does not parse", name)
	}
	if v := tags["v"]; v != "" && v != "DKIM1" {
		return nil, fmt.Errorf("key record at %s has v=%s", name, v)
	}
	p := tags.compact("p")
	if p == "" {
		return nil, fmt.Errorf("key at %s is revoked", name)
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, fmt.Errorf("key at %s is not base64", name)
	}
	switch strings.ToLower(tags["k"]) {
	case "", "rsa":
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			pub, err = x509.ParsePKCS1PublicKey(der)
		}
		if err != nil {
			return nil, fmt.Errorf("key at %s does not parse", name)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key at %s is not rsa", name)
		}
		if rsaPub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("key at %s is only %d bits", name, rsaPub.N.BitLen())
		}
		return rsaPub, nil
	case "ed25519":
		if len(der) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key at %s is not an ed25519 key", name)
		}
		return ed25519.PublicKey(der), nil
	}
	return nil, fmt.Errorf("key at %s has unsupported k=%s", name, tags["k"])
}
