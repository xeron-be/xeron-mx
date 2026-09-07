package spam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

type Action string

const (
	ActionNone Action = "no action"

	ActionGreylist Action = "greylist"

	ActionAddHeader Action = "add header"

	ActionRewriteSubject Action = "rewrite subject"

	ActionSoftReject Action = "soft reject"

	ActionReject Action = "reject"
)

type Verdict struct {
	Action Action
	Score  float64

	Required float64

	Symbols []string

	Skipped bool

	Reason string
}

func (v Verdict) Reject() bool { return v.Action == ActionReject }

func (v Verdict) Defer() bool {
	return v.Action == ActionSoftReject || v.Action == ActionGreylist
}

func (v Verdict) Spammy() bool {
	return v.Action == ActionAddHeader || v.Action == ActionRewriteSubject || v.Reject()
}

type Checker struct {
	cfg    config.SpamConfig
	client *http.Client
	log    *slog.Logger
}

func New(cfg config.SpamConfig, log *slog.Logger) *Checker {
	return &Checker{
		cfg: cfg,
		log: log,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 4,

				DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			},
		},
	}
}

func (c *Checker) Enabled() bool { return c.cfg.Enabled && c.cfg.URL != "" }

func (c *Checker) DeferAllowed() bool { return c.cfg.DeferEnabled }

type Envelope struct {
	From       string
	To         []string
	HeloName   string
	RemoteAddr string
	QueueID    string
}

func (c *Checker) Check(ctx context.Context, env Envelope, body io.Reader, size int64) Verdict {
	if !c.Enabled() {
		return Verdict{Action: ActionNone, Skipped: true, Reason: "filtering disabled"}
	}
	if c.cfg.MaxSizeBytes > 0 && size > c.cfg.MaxSizeBytes {

		return Verdict{Action: ActionNone, Skipped: true, Reason: "message larger than the scan limit"}
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	endpoint := strings.TrimSuffix(c.cfg.URL, "/") + "/checkv2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return c.skip("could not build the scan request", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	if env.From != "" {
		req.Header.Set("From", env.From)
	}
	for _, rcpt := range env.To {
		req.Header.Add("Rcpt", rcpt)
	}
	if len(env.To) > 0 {
		req.Header.Set("Deliver-To", env.To[0])
	}
	if env.HeloName != "" {
		req.Header.Set("Helo", env.HeloName)
	}
	if ip := hostOnly(env.RemoteAddr); ip != "" {
		req.Header.Set("IP", ip)
	}
	if env.QueueID != "" {
		req.Header.Set("Queue-Id", env.QueueID)
	}
	if c.cfg.Password != "" {
		req.Header.Set("Password", c.cfg.Password)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return c.skip("rspamd is unreachable", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return c.skip(fmt.Sprintf("rspamd answered %d", resp.StatusCode),
			fmt.Errorf("%s", bytes.TrimSpace(snippet)))
	}

	var parsed struct {
		Action    string  `json:"action"`
		Score     float64 `json:"score"`
		Required  float64 `json:"required_score"`
		IsSkipped bool    `json:"is_skipped"`
		Symbols   map[string]struct {
			Score float64 `json:"score"`
		} `json:"symbols"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return c.skip("could not parse the rspamd response", err)
	}
	action := Action(strings.ToLower(strings.TrimSpace(parsed.Action)))
	if action == "" {
		action = ActionNone
	}

	if parsed.IsSkipped && action == ActionNone {
		return Verdict{Action: ActionNone, Skipped: true, Reason: "rspamd skipped the message"}
	}

	symbols := make([]string, 0, len(parsed.Symbols))
	for name, sym := range parsed.Symbols {
		if sym.Score != 0 {
			symbols = append(symbols, name)
		}
	}

	if action == ActionReject && !c.cfg.RejectEnabled {
		action = ActionAddHeader
	}

	return Verdict{
		Action:   action,
		Score:    parsed.Score,
		Required: parsed.Required,
		Symbols:  symbols,
	}
}

func (c *Checker) skip(reason string, err error) Verdict {

	c.log.Warn("spam check skipped, accepting the message anyway",
		"reason", reason, "error", err)
	return Verdict{Action: ActionNone, Skipped: true, Reason: reason}
}

func Headers(action string, score *float64) string {
	if action == "" || action == string(ActionNone) {
		return ""
	}
	var b strings.Builder
	b.WriteString("X-Spam-Checked-By: XeronMX\r\n")
	b.WriteString("X-Spam-Action: " + sanitizeHeader(action) + "\r\n")
	if score != nil {
		fmt.Fprintf(&b, "X-Spam-Score: %.2f\r\n", *score)
	}
	if action == string(ActionAddHeader) || action == string(ActionRewriteSubject) ||
		action == string(ActionReject) {
		b.WriteString("X-Spam-Flag: YES\r\n")
	}
	return b.String()
}

func sanitizeHeader(s string) string {

	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
