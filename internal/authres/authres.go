package authres

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"golang.org/x/net/publicsuffix"

	"github.com/xeron-be/xeron-mx/internal/arc"
)

const (
	DefaultTimeout = 10 * time.Second
	maxSignatures  = 5
)

type Checker struct {
	Resolver spf.DNSResolver
	Timeout  time.Duration
}

type Signature struct {
	Domain string
	Result string
}

type Result struct {
	SPF       string
	SPFDomain string
	SPFHelo   bool
	DKIM      []Signature
	ARC       string
}

func (c *Checker) resolver() spf.DNSResolver {
	if c != nil && c.Resolver != nil {
		return c.Resolver
	}
	return net.DefaultResolver
}

func (c *Checker) timeout() time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Checker) SPF(ctx context.Context, ip net.IP, helo, mailFrom string) Result {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	res, _ := spf.CheckHostWithSender(ip, helo, mailFrom,
		spf.WithContext(ctx), spf.WithResolver(c.resolver()))

	r := Result{SPF: string(res), SPFDomain: domainOf(mailFrom)}
	if r.SPFDomain == "" {
		r.SPFDomain = strings.ToLower(strings.TrimSuffix(helo, "."))
		r.SPFHelo = true
	}
	return r
}

func (c *Checker) DKIM(ctx context.Context, r io.Reader) []Signature {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	defer io.Copy(io.Discard, r)

	res := c.resolver()
	verifications, _ := dkim.VerifyWithOptions(r, &dkim.VerifyOptions{
		LookupTXT:        func(name string) ([]string, error) { return res.LookupTXT(ctx, name) },
		MaxVerifications: maxSignatures,
	})

	out := make([]Signature, 0, len(verifications))
	for _, v := range verifications {
		out = append(out, Signature{Domain: strings.ToLower(v.Domain), Result: dkimResult(v.Err)})
	}
	return out
}

func (c *Checker) ARC(ctx context.Context, r io.Reader) string {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	raw, err := io.ReadAll(r)
	if err != nil {
		return "temperror"
	}
	return arc.Verify(ctx, raw, c.resolver()).CV
}

func dkimResult(err error) string {
	switch {
	case err == nil:
		return "pass"
	case dkim.IsPermFail(err):
		return "permerror"
	case dkim.IsTempFail(err):
		return "temperror"
	default:
		return "fail"
	}
}

func (r Result) Header() string {
	if r.SPF == "" && len(r.DKIM) == 0 && r.ARC == "" {
		return ""
	}
	var parts []string
	if r.SPF != "" {
		prop := "smtp.mailfrom"
		if r.SPFHelo {
			prop = "smtp.helo"
		}
		p := "spf=" + token(r.SPF)
		if d := token(r.SPFDomain); d != "" {
			p += " " + prop + "=" + d
		}
		parts = append(parts, p)
	}
	if len(r.DKIM) == 0 {
		parts = append(parts, "dkim=none")
	}
	for _, s := range r.DKIM {
		p := "dkim=" + token(s.Result)
		if d := token(s.Domain); d != "" {
			p += " header.d=" + d
		}
		parts = append(parts, p)
	}
	if r.ARC != "" {
		parts = append(parts, "arc="+token(r.ARC))
	}
	return strings.Join(parts, "; ")
}

func ARCResult(header string) string {
	for _, part := range strings.Split(header, ";") {
		method, rest, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(method, "arc") {
			return strings.ToLower(strings.Fields(rest + " ")[0])
		}
	}
	return ""
}

func (r Result) Authenticates(mailFrom string) bool {
	domain := domainOf(mailFrom)
	if domain == "" {
		return false
	}
	if r.SPF == string(spf.Pass) && !r.SPFHelo && r.SPFDomain == domain {
		return true
	}
	for _, s := range r.DKIM {
		if s.Result == "pass" && aligned(s.Domain, domain) {
			return true
		}
	}
	return false
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(addr[at+1:], "."))
}

func aligned(a, b string) bool {
	oa, ob := orgDomain(a), orgDomain(b)
	return oa != "" && oa == ob
}

func orgDomain(d string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(strings.TrimSuffix(d, ".")))
	if err != nil {
		return ""
	}
	return org
}

func token(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return -1
	}, s)
}
