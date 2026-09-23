package sender

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/dkim"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/spam"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func (s *Sender) sendOutbound(ctx context.Context, m *store.Message, body io.Reader) (recipients, error) {
	body, err := s.signed(ctx, m, body)
	if err != nil {
		return recipients{}, err
	}

	mode, route := s.routeFor(ctx, m)
	if !s.outbound.Enabled {
		mode, route = "direct", nil
	}
	switch mode {
	case "relay":
		return s.sendViaRelay(ctx, m, body, route)
	case "direct":
		return s.sendDirect(ctx, m, body)
	default:

		return recipients{}, fmt.Errorf("outbound: unknown mode %q", mode)
	}
}

func (s *Sender) signed(ctx context.Context, m *store.Message, body io.Reader) (io.Reader, error) {
	if s.db == nil {
		return body, nil
	}
	key, err := s.db.DKIMKeyFor(ctx, m.DomainID)
	if err != nil || !key.Enabled {
		return body, nil
	}

	d, err := s.db.DomainByID(ctx, m.DomainID)
	if err != nil {
		return body, nil
	}

	pem, err := s.blobs.Unseal(key.PrivateKey)
	if err != nil {
		s.log.Error("dkim key unreadable, sending unsigned", "domain", d.Name, "error", err)
		return body, nil
	}
	signer, err := dkim.NewSigner(d.Name, key.Selector, pem)
	if err != nil {
		s.log.Error("dkim key unusable, sending unsigned", "domain", d.Name, "error", err)
		return body, nil
	}

	var out bytes.Buffer
	if err := signer.Sign(&out, body); err != nil {
		s.log.Error("dkim signing failed, sending unsigned", "domain", d.Name, "error", err)
		return nil, fmt.Errorf("dkim: signing failed and the body has been consumed: %w", err)
	}
	s.log.Debug("message signed", "domain", d.Name, "selector", key.Selector)
	return &out, nil
}

func (s *Sender) routeFor(ctx context.Context, m *store.Message) (string, *store.Route) {
	if s.db == nil || len(m.EnvelopeTo) == 0 {
		return s.outbound.Mode, nil
	}
	at := strings.LastIndex(m.EnvelopeTo[0], "@")
	if at < 0 {
		return s.outbound.Mode, nil
	}

	r, err := s.db.RouteFor(ctx, m.EnvelopeTo[0][at+1:])
	if err != nil {
		return s.outbound.Mode, nil
	}
	s.log.Debug("outbound route matched", "destination", r.Destination, "mode", r.Mode)
	return r.Mode, r
}

func (s *Sender) sendViaRelay(ctx context.Context, m *store.Message, body io.Reader, override *store.Route) (recipients, error) {
	host, port, mode := s.outbound.RelayHost, s.outbound.RelayPort, s.outbound.RelayTLS
	username, password := s.outbound.RelayUsername, s.outbound.RelayPassword

	if override != nil && override.RelayHost != "" {
		host, port, mode = override.RelayHost, override.RelayPort, override.RelayTLS
		username = override.RelayUsername
		password = ""
		if len(override.RelayPassword) > 0 {
			clear, err := s.blobs.Unseal(override.RelayPassword)
			if err != nil {
				return recipients{}, fmt.Errorf("route %s: stored relay password unreadable: %w",
					override.Destination, err)
			}
			password = string(clear)
		}
	}

	route := &store.Domain{
		PrimaryHost: host,
		PrimaryPort: port,
		PrimaryTLS:  mode,
		Name:        host,
	}

	client, err := smtpclient.Dial(ctx, route, s.heloName())
	if err != nil {
		return recipients{}, err
	}
	defer client.Close()

	if username != "" {
		ok, _ := client.Extension("AUTH")
		if !ok {
			return recipients{}, fmt.Errorf("relay %s does not offer AUTH but credentials are configured", host)
		}
		if err := client.Auth(sasl.NewPlainClient("", username, password)); err != nil {
			s.log.Error("relay refused the configured credentials; mail is held until they are fixed",
				"relay", host, "username", username, "error", err)
			return recipients{}, fmt.Errorf("relay %s refused the configured credentials: %v", host, err)
		}
	}

	res, err := transmit(client, m, body, s.spamHeaders(m))
	if m.EnvelopeFrom == "" && refusedNullSender(err) {
		fallback := BounceSender(s.heloName())
		s.log.Warn("relay refuses the null sender, sending the bounce from "+fallback,
			"relay", host, "id", m.ID, "error", err)
		if rerr := client.Reset(); rerr != nil {
			return recipients{}, err
		}
		retry := *m
		retry.EnvelopeFrom = fallback
		return transmit(client, &retry, body, s.spamHeaders(m))
	}
	return res, err
}

func BounceSender(hostname string) string { return "MAILER-DAEMON@" + hostname }

var errMailFrom = errors.New("MAIL FROM")

func refusedNullSender(err error) bool {
	var reply *smtp.SMTPError
	return errors.Is(err, errMailFrom) && errors.As(err, &reply) && reply.Code >= 500 && reply.Code < 600
}

func (s *Sender) sendDirect(ctx context.Context, m *store.Message, body io.Reader) (recipients, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return recipients{}, fmt.Errorf("read message: %w", err)
	}

	var all recipients
	byDomain := map[string][]string{}
	var domains []string
	for _, rcpt := range m.EnvelopeTo {
		at := strings.LastIndex(rcpt, "@")
		if at < 0 || at == len(rcpt)-1 {
			all.rejected = append(all.rejected, recipientFailure{rcpt, &smtp.SMTPError{
				Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "malformed recipient " + rcpt}})
			continue
		}
		d := strings.ToLower(rcpt[at+1:])
		if _, seen := byDomain[d]; !seen {
			domains = append(domains, d)
		}
		byDomain[d] = append(byDomain[d], rcpt)
	}

	for _, domain := range domains {
		rcpts := byDomain[domain]
		res, err := s.directTo(ctx, m, domain, rcpts, raw)
		if err == nil {
			all.accepted = append(all.accepted, res.accepted...)
			all.deferred = append(all.deferred, res.deferred...)
			all.rejected = append(all.rejected, res.rejected...)
			continue
		}
		var reply *smtp.SMTPError
		permanent := errors.As(err, &reply) && reply.Code >= 500 && reply.Code < 600
		for _, rcpt := range rcpts {
			if permanent {
				all.rejected = append(all.rejected, recipientFailure{rcpt, err})
			} else {
				all.deferred = append(all.deferred, recipientFailure{rcpt, err})
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return all, nil
}

func (s *Sender) directTo(ctx context.Context, m *store.Message, domain string, rcpts []string, raw []byte) (recipients, error) {
	hosts, err := lookupMX(ctx, s.mxResolver(), domain)
	if err != nil {
		return recipients{}, fmt.Errorf("MX lookup for %s: %w", domain, err)
	}

	part := *m
	part.EnvelopeTo = rcpts
	var lastErr error
	for _, host := range hosts {
		addr, port := host, 25
		if s.directAddr != nil {
			addr, port = s.directAddr(host)
		}
		route := &store.Domain{
			Name:        domain,
			PrimaryHost: addr,
			PrimaryPort: port,
			PrimaryTLS:  "opportunistic",
		}
		client, err := smtpclient.Dial(ctx, route, s.heloName())
		if err != nil {
			lastErr = err
			continue
		}
		res, err := transmit(client, &part, bytes.NewReader(raw), s.spamHeaders(m))
		client.Close()
		if err == nil {
			return res, nil
		}
		lastErr = err
		break
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no MX host for %s accepted the message", domain)
	}
	return recipients{}, lastErr
}

type mxLookup interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

func (s *Sender) mxResolver() mxLookup {
	if s.resolver != nil {
		return s.resolver
	}
	return net.DefaultResolver
}

func notFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func lookupMX(ctx context.Context, resolver mxLookup, domain string) ([]string, error) {
	records, err := resolver.LookupMX(ctx, domain)
	if err != nil && !notFound(err) {
		return nil, err
	}
	if len(records) == 0 {
		_, aErr := resolver.LookupHost(ctx, domain)
		switch {
		case aErr == nil:
			return []string{domain}, nil
		case notFound(aErr):
			return nil, &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 2},
				Message: domain + " has no MX and no address, it cannot receive mail"}
		default:
			return nil, aErr
		}
	}

	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	hosts := make([]string, 0, len(records))
	for _, r := range records {
		host := strings.TrimSuffix(r.Host, ".")
		if host == "" {
			return nil, &smtp.SMTPError{Code: 556, EnhancedCode: smtp.EnhancedCode{5, 1, 10},
				Message: domain + " publishes a null MX and accepts no mail"}
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

type recipientFailure struct {
	rcpt string
	err  error
}

type recipients struct {
	accepted []string
	deferred []recipientFailure
	rejected []recipientFailure
}

func addresses(failures []recipientFailure) []string {
	out := make([]string, len(failures))
	for i, f := range failures {
		out[i] = f.rcpt
	}
	return out
}

func transmit(client *smtp.Client, m *store.Message, body io.Reader, extraHeaders string) (recipients, error) {
	var res recipients
	if err := client.Mail(m.EnvelopeFrom, nil); err != nil {
		return recipients{}, fmt.Errorf("%w: %w", errMailFrom, err)
	}
	for _, rcpt := range m.EnvelopeTo {
		err := client.Rcpt(rcpt, nil)
		var reply *smtp.SMTPError
		switch {
		case err == nil:
			res.accepted = append(res.accepted, rcpt)
		case errors.As(err, &reply) && reply.Code >= 500 && reply.Code < 600:
			res.rejected = append(res.rejected, recipientFailure{rcpt, fmt.Errorf("RCPT TO %s: %w", rcpt, err)})
		case errors.As(err, &reply):
			res.deferred = append(res.deferred, recipientFailure{rcpt, fmt.Errorf("RCPT TO %s: %w", rcpt, err)})
		default:
			return recipients{}, fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}
	if len(res.accepted) == 0 {
		_ = client.Quit()
		return res, nil
	}

	w, err := client.Data()
	if err != nil {
		return recipients{}, fmt.Errorf("DATA: %w", err)
	}

	if extraHeaders != "" {
		if _, err := io.WriteString(w, extraHeaders); err != nil {
			w.Close()
			return recipients{}, fmt.Errorf("write headers: %w", err)
		}
	}
	if _, err := io.Copy(w, body); err != nil {
		w.Close()
		return recipients{}, fmt.Errorf("write body: %w", err)
	}

	if err := w.Close(); err != nil {
		return recipients{}, fmt.Errorf("finish DATA: %w", err)
	}
	_ = client.Quit()
	return res, nil
}

func (s *Sender) heloName() string {
	if s.hostname != "" {
		return s.hostname
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "xeronmx.local"
	}
	return host
}

func (s *Sender) spamHeaders(m *store.Message) string {
	return spam.Headers(m.SpamAction, m.SpamScore)
}
