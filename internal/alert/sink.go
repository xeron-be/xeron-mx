package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-sasl"

	"github.com/xeron-be/xeron-mx/internal/mailutil"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/webhook"
)

const (
	SignatureHeader = webhook.SignatureHeader
	TimestampHeader = webhook.TimestampHeader
)

func (a *Alerter) postWebhook(ctx context.Context, al Alert) error {
	body, err := json.Marshal(al)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "XeronMX")

	webhook.SignRequest(req, []byte(a.cfg.Webhook.Secret), body, time.Now())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %d", resp.StatusCode)
	}
	return nil
}

func (a *Alerter) sendEmail(ctx context.Context, al Alert) error {
	cfg := a.cfg.Email

	port := cfg.Port
	if port == 0 {
		port = 587
	}
	mode := cfg.TLS
	if mode == "" {
		mode = smtpclient.TLSRequired
	}

	route := &store.Domain{
		Name:        cfg.Host,
		PrimaryHost: cfg.Host,
		PrimaryPort: port,
		PrimaryTLS:  mode,
	}

	client, err := smtpclient.Dial(ctx, route, a.host)
	if err != nil {
		return err
	}
	defer client.Close()

	if cfg.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("relay %s does not offer AUTH but credentials are configured", cfg.Host)
		}
		if err := client.Auth(sasl.NewPlainClient("", cfg.Username, cfg.Password)); err != nil {
			return fmt.Errorf("relay rejected the credentials: %w", err)
		}
	}

	if err := client.Mail(cfg.From, nil); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, rcpt := range cfg.To {
		if err := client.Rcpt(rcpt, nil); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := io.WriteString(w, a.message(al)); err != nil {
		w.Close()
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finish DATA: %w", err)
	}
	client.Quit()
	return nil
}

func (a *Alerter) message(al Alert) string {
	id, err := mailutil.NewID()
	if err != nil {
		id = fmt.Sprintf("%d", al.At.UnixNano())
	}

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", header(a.cfg.Email.From))
	fmt.Fprintf(&b, "To: %s\r\n", header(strings.Join(a.cfg.Email.To, ", ")))
	fmt.Fprintf(&b, "Subject: [XeronMX %s] %s\r\n", header(strings.ToUpper(al.Severity)), header(al.Title))
	fmt.Fprintf(&b, "Date: %s\r\n", al.At.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", id, header(a.host))
	fmt.Fprintf(&b, "Auto-Submitted: auto-generated\r\n")
	fmt.Fprintf(&b, "X-XeronMX-Alert: %s\r\n", header(al.Key))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "%s\r\n\r\n", al.Title)
	fmt.Fprintf(&b, "%s\r\n\r\n", al.Detail)
	fmt.Fprintf(&b, "Host:  %s\r\n", a.host)
	fmt.Fprintf(&b, "When:  %s\r\n", al.At.Format(time.RFC3339))
	if detail := describe(al.Data); detail != "" {
		b.WriteString("\r\nDetail:\r\n")
		b.WriteString(detail)
	}
	b.WriteString("\r\n-- \r\nSent by XeronMX. This mailbox is not monitored.\r\n")
	return b.String()
}

func header(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}
