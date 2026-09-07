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

func (s *Sender) sendOutbound(ctx context.Context, m *store.Message, body io.Reader) error {
	body, err := s.signed(ctx, m, body)
	if err != nil {
		return err
	}

	mode, route := s.routeFor(ctx, m)
	switch mode {
	case "relay":
		return s.sendViaRelay(ctx, m, body, route)
	case "direct":
		return s.sendDirect(ctx, m, body)
	default:

		return fmt.Errorf("outbound: unknown mode %q", mode)
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

func (s *Sender) sendViaRelay(ctx context.Context, m *store.Message, body io.Reader, override *store.Route) error {
	host, port, mode := s.outbound.RelayHost, s.outbound.RelayPort, s.outbound.RelayTLS
	username, password := s.outbound.RelayUsername, s.outbound.RelayPassword

	if override != nil && override.RelayHost != "" {
		host, port, mode = override.RelayHost, override.RelayPort, override.RelayTLS
		username = override.RelayUsername
		password = ""
		if len(override.RelayPassword) > 0 {
			clear, err := s.blobs.Unseal(override.RelayPassword)
			if err != nil {
				return fmt.Errorf("route %s: stored relay password unreadable: %w",
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
		return err
	}
	defer client.Close()

	if username != "" {
		ok, _ := client.Extension("AUTH")
		if !ok {
			return fmt.Errorf("relay %s does not offer AUTH but credentials are configured", host)
		}
		if err := client.Auth(sasl.NewPlainClient("", username, password)); err != nil {

			return &smtp.SMTPError{
				Code:         535,
				EnhancedCode: smtp.EnhancedCode{5, 7, 8},
				Message:      "relay rejected the configured credentials: " + err.Error(),
			}
		}
	}

	return transmit(client, m, body, s.spamHeaders(m))
}

func (s *Sender) sendDirect(ctx context.Context, m *store.Message, body io.Reader) error {

	byDomain := map[string][]string{}
	for _, rcpt := range m.EnvelopeTo {
		at := strings.LastIndex(rcpt, "@")
		if at < 0 {
			return &smtp.SMTPError{Code: 550, Message: "malformed recipient " + rcpt}
		}
		d := strings.ToLower(rcpt[at+1:])
		byDomain[d] = append(byDomain[d], rcpt)
	}
	if len(byDomain) > 1 {
		return fmt.Errorf("outbound: message has recipients in %d domains; "+
			"direct mode delivers one domain per message", len(byDomain))
	}

	var domain string
	for d := range byDomain {
		domain = d
	}

	hosts, err := lookupMX(ctx, domain)
	if err != nil {
		return fmt.Errorf("MX lookup for %s: %w", domain, err)
	}

	var lastErr error
	for _, host := range hosts {
		route := &store.Domain{
			Name:        domain,
			PrimaryHost: host,
			PrimaryPort: 25,

			PrimaryTLS: "opportunistic",
		}
		client, err := smtpclient.Dial(ctx, route, s.heloName())
		if err != nil {
			lastErr = err
			continue
		}
		err = transmit(client, m, body, s.spamHeaders(m))
		client.Close()
		if err == nil {
			return nil
		}
		var permanent *smtp.SMTPError
		if errors.As(err, &permanent) && permanent.Code >= 500 && permanent.Code < 600 {
			return err
		}
		lastErr = err

		break
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no MX host for %s accepted the message", domain)
	}
	return lastErr
}

func lookupMX(ctx context.Context, domain string) ([]string, error) {
	resolver := &net.Resolver{}
	records, err := resolver.LookupMX(ctx, domain)
	if err != nil {

		if _, aErr := resolver.LookupHost(ctx, domain); aErr == nil {
			return []string{domain}, nil
		}
		return nil, err
	}
	if len(records) == 0 {
		return []string{domain}, nil
	}

	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
	hosts := make([]string, 0, len(records))
	for _, r := range records {
		host := strings.TrimSuffix(r.Host, ".")

		if host == "" {
			return nil, fmt.Errorf("%s publishes a null MX and accepts no mail", domain)
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func transmit(client *smtp.Client, m *store.Message, body io.Reader, extraHeaders string) error {
	if err := client.Mail(m.EnvelopeFrom, nil); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, rcpt := range m.EnvelopeTo {
		if err := client.Rcpt(rcpt, nil); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}

	if extraHeaders != "" {
		if _, err := io.WriteString(w, extraHeaders); err != nil {
			w.Close()
			return fmt.Errorf("write headers: %w", err)
		}
	}
	if _, err := io.Copy(w, body); err != nil {
		w.Close()
		return fmt.Errorf("write body: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("finish DATA: %w", err)
	}
	_ = client.Quit()
	return nil
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
