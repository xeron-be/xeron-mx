package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type statusResponse struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Queue   struct {
		Pending      int64 `json:"pending"`
		PendingBytes int64 `json:"pending_bytes"`
		Total        int64 `json:"total"`
		MaxMessages  int64 `json:"max_messages"`
		MaxBytes     int64 `json:"max_bytes"`
	} `json:"queue"`
	Domains []struct {
		Name      string     `json:"name"`
		Enabled   bool       `json:"enabled"`
		IsUp      bool       `json:"is_up"`
		Pending   int64      `json:"pending"`
		LastError string     `json:"last_error"`
		LastCheck *time.Time `json:"last_check"`
	} `json:"domains"`
	AllPrimariesUp bool  `json:"all_primaries_up"`
	Quarantined    int64 `json:"quarantined"`
	TLS            *struct {
		Source    string `json:"source"`
		Domain    string `json:"domain"`
		LastError string `json:"last_error"`
	} `json:"tls"`
}

func cmdStatus(ctx context.Context, c *Client) error {
	var st statusResponse
	if err := c.get(ctx, "/api/v1/status", &st); err != nil {
		return err
	}
	if jsonOut {
		return emit(st)
	}

	note("XeronMX %s", st.Version)
	note("queue       %d pending, %s (%d total)",
		st.Queue.Pending, bytesHuman(st.Queue.PendingBytes), st.Queue.Total)
	if st.Quarantined > 0 {
		note("quarantine  %d held", st.Quarantined)
	}
	if st.TLS != nil {
		line := fmt.Sprintf("tls         %s for %s", st.TLS.Source, st.TLS.Domain)
		if st.TLS.Source == "self-signed" {
			line += "  (interim; no CA certificate yet)"
		}
		note("%s", line)
		if st.TLS.LastError != "" {
			warn("            last ACME error: %s", st.TLS.LastError)
		}
	}
	note("")

	if len(st.Domains) == 0 {
		note("No domains configured.")
		return nil
	}

	t := newTable("DOMAIN", "PRIMARY", "PENDING", "CHECKED", "ERROR")
	for _, d := range st.Domains {
		state := "up"
		switch {
		case !d.Enabled:
			state = "disabled"
		case !d.IsUp:
			state = "DOWN"
		}
		t.row(d.Name, state, strconv.FormatInt(d.Pending, 10),
			ago(d.LastCheck), truncate(d.LastError, 50))
	}
	t.flush()

	if !st.AllPrimariesUp {
		note("")
		note("At least one primary is down. Mail is being held, not lost.")
	}
	return nil
}

type domain struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	PrimaryHost string `json:"primary_host"`
	PrimaryPort int    `json:"primary_port"`
	PrimaryTLS  string `json:"primary_tls"`
	Retention   int    `json:"retention_hours"`
	Enabled     bool   `json:"enabled"`
	Pending     int64  `json:"pending"`
	Primary     *struct {
		IsUp bool `json:"is_up"`
	} `json:"primary"`
}

func cmdDomains(ctx context.Context, c *Client, args []string) error {
	sub, rest := split(args, "list")
	switch sub {
	case "list":
		var body struct {
			Domains []domain `json:"domains"`
		}
		if err := c.get(ctx, "/api/v1/domains", &body); err != nil {
			return err
		}
		if jsonOut {
			return emit(body.Domains)
		}
		if len(body.Domains) == 0 {
			note("No domains configured.")
			return nil
		}
		t := newTable("ID", "DOMAIN", "PRIMARY", "TLS", "RETENTION", "PENDING", "STATE")
		for _, d := range body.Domains {
			state := "enabled"
			if !d.Enabled {
				state = "disabled"
			} else if d.Primary != nil && !d.Primary.IsUp {
				state = "primary down"
			}
			t.row(strconv.FormatInt(d.ID, 10), d.Name,
				fmt.Sprintf("%s:%d", d.PrimaryHost, d.PrimaryPort), d.PrimaryTLS,
				fmt.Sprintf("%dh", d.Retention),
				strconv.FormatInt(d.Pending, 10), state)
		}
		t.flush()
		return nil

	case "add":
		fs := flag.NewFlagSet("domains add", flag.ContinueOnError)
		port := fs.Int("port", 25, "port on the primary")
		tlsMode := fs.String("tls", "starttls", "none | opportunistic | starttls | tls")
		retention := fs.Int("retention-hours", 168, "how long to hold undeliverable mail")
		args, err := parseMixed(fs, rest)
		if err != nil {
			return err
		}
		if len(args) != 2 {
			return errors.New("usage: xeronmxctl domains add <domain> <primary-host> [flags]")
		}

		var created domain
		err = c.post(ctx, "/api/v1/domains", map[string]any{
			"name":            args[0],
			"primary_host":    args[1],
			"primary_port":    *port,
			"primary_tls":     *tlsMode,
			"retention_hours": *retention,
		}, &created)
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(created)
		}
		note("Added %s (id %d), holding for %s.",
			created.Name, created.ID, fmt.Sprintf("%dh", created.Retention))
		note("Publish a secondary MX record for it, then run: xeronmxctl domains test %d", created.ID)
		return nil

	case "rm":
		fs := flag.NewFlagSet("domains rm", flag.ContinueOnError)
		force := fs.Bool("force", false, "delete even though mail is queued for it")
		args, err := parseMixed(fs, rest)
		if err != nil {
			return err
		}
		if len(args) != 1 {
			return errors.New("usage: xeronmxctl domains rm <id> [--force]")
		}
		path := "/api/v1/domains/" + args[0]
		if *force {
			path += "?force=true"
		}
		var body map[string]any
		if err = c.delete(ctx, path, &body); err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.Status == 409 {
				return fmt.Errorf("%s\n  pass --force to delete it and the mail with it", apiErr.Message)
			}
			return err
		}
		note("Deleted.")
		return nil

	case "test":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl domains test <id>")
		}
		var probe struct {
			Reachable bool   `json:"reachable"`
			TookMS    int64  `json:"took_ms"`
			Error     string `json:"error"`
			Hint      string `json:"hint"`
		}
		if err := c.post(ctx, "/api/v1/domains/"+rest[0]+"/test", nil, &probe); err != nil {
			return err
		}
		if jsonOut {
			return emit(probe)
		}
		if probe.Reachable {
			note("The primary answered in %dms.", probe.TookMS)
			return nil
		}
		warn("The primary did not answer: %s", probe.Error)
		if probe.Hint != "" {
			warn("  %s", probe.Hint)
		}
		return nil

	case "recipients":
		fs := flag.NewFlagSet("domains recipients", flag.ContinueOnError)
		file := fs.String("file", "", "replace the list with the addresses in this file, one per line (- for stdin)")
		clear := fs.Bool("clear", false, "remove the list, so that every address is accepted again")
		args, err := parseMixed(fs, rest)
		if err != nil {
			return err
		}
		if len(args) != 1 || (*file != "" && *clear) {
			return errors.New("usage: xeronmxctl domains recipients <id> [--file <path|-> | --clear]")
		}
		path := "/api/v1/domains/" + args[0] + "/recipients"

		var body struct {
			Recipients []string `json:"recipients"`
		}
		switch {
		case *clear:
			err = c.put(ctx, path, map[string]any{"recipients": []string{}}, &body)
		case *file != "":
			var raw []byte
			if *file == "-" {
				raw, err = io.ReadAll(os.Stdin)
			} else {
				raw, err = os.ReadFile(*file)
			}
			if err != nil {
				return err
			}
			var list []string
			for _, line := range strings.Split(string(raw), "\n") {
				if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
					list = append(list, line)
				}
			}
			err = c.put(ctx, path, map[string]any{"recipients": list}, &body)
		default:
			err = c.get(ctx, path, &body)
		}
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(body.Recipients)
		}
		if len(body.Recipients) == 0 {
			note("No list: every address in the domain is accepted.")
			return nil
		}
		for _, r := range body.Recipients {
			fmt.Println(r)
		}
		if *file != "" {
			note("%d addresses; any other is refused with 550 5.1.1.", len(body.Recipients))
		}
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q (try list, add, rm, test, recipients)", sub)
	}
}

type message struct {
	ID          string     `json:"id"`
	From        string     `json:"from"`
	To          []string   `json:"to"`
	Subject     string     `json:"subject"`
	SizeBytes   int64      `json:"size_bytes"`
	ReceivedAt  time.Time  `json:"received_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	NextRetryAt *time.Time `json:"next_retry_at"`
	LastError   string     `json:"last_error"`
	Direction   string     `json:"direction"`
	Quarantined *time.Time `json:"quarantined_at"`
	QuarReason  string     `json:"quarantine_reason"`
	SpamScore   *float64   `json:"spam_score"`
}

func cmdQueue(ctx context.Context, c *Client, args []string) error {
	sub, rest := split(args, "list")
	switch sub {
	case "list":
		fs := flag.NewFlagSet("queue list", flag.ContinueOnError)
		status := fs.String("status", "", "queued | delivering | delivered | failed | expired")
		direction := fs.String("direction", "", "inbound | outbound")
		limit := fs.Int("limit", 50, "how many to show")
		quarantined := fs.Bool("quarantined", false, "only messages held in quarantine")
		if err := fs.Parse(rest); err != nil {
			return err
		}

		q := url.Values{}
		if *status != "" {
			q.Set("status", *status)
		}
		if *direction != "" {
			q.Set("direction", *direction)
		}
		if *quarantined {
			q.Set("quarantined", "true")
		}
		q.Set("limit", strconv.Itoa(*limit))

		var body struct {
			Messages []message `json:"messages"`
			Count    int       `json:"count"`
		}
		if err := c.get(ctx, "/api/v1/queue?"+q.Encode(), &body); err != nil {
			return err
		}
		if jsonOut {
			return emit(body.Messages)
		}
		if len(body.Messages) == 0 {
			note("Nothing in the queue.")
			return nil
		}
		t := newTable("ID", "STATUS", "FROM", "TO", "SUBJECT", "SIZE", "TRIES", "AGE")
		for _, m := range body.Messages {
			received := m.ReceivedAt
			state := m.Status
			if m.Quarantined != nil {
				state = "quarantined"
			}
			t.row(truncate(m.ID, 12), state,
				truncate(m.From, 24), truncate(strings.Join(m.To, ","), 24),
				truncate(m.Subject, 30), bytesHuman(m.SizeBytes),
				strconv.Itoa(m.Attempts), ago(&received))
		}
		t.flush()
		note("")
		note("%d shown of %d matching.", len(body.Messages), body.Count)
		return nil

	case "show":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl queue show <id>")
		}
		var m message
		if err := c.get(ctx, "/api/v1/queue/"+rest[0], &m); err != nil {
			return err
		}
		if jsonOut {
			return emit(m)
		}
		received, expires := m.ReceivedAt, m.ExpiresAt
		note("id          %s", m.ID)
		note("status      %s (%s)", m.Status, m.Direction)
		note("from        %s", m.From)
		note("to          %s", strings.Join(m.To, ", "))
		note("subject     %s", m.Subject)
		note("size        %s", bytesHuman(m.SizeBytes))
		note("received    %s", ago(&received))
		note("expires     %s", until(&expires))
		note("attempts    %d", m.Attempts)
		if m.NextRetryAt != nil {
			note("next try    %s", until(m.NextRetryAt))
		}
		if m.SpamScore != nil {
			note("spam score  %.1f", *m.SpamScore)
		}
		if m.Quarantined != nil {
			note("quarantine  %s", m.QuarReason)
		}
		if m.LastError != "" {
			note("last error  %s", m.LastError)
		}
		note("")
		note("The body is not shown here. Reading it is an audited action:")
		note("  curl -H \"Authorization: Bearer $XERONMX_TOKEN\" %s/api/v1/queue/%s/raw", c.base, m.ID)
		return nil

	case "retry":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl queue retry <id>")
		}
		if err := c.post(ctx, "/api/v1/queue/"+rest[0]+"/retry", nil, nil); err != nil {
			return err
		}
		note("Queued for immediate delivery.")
		return nil

	case "rm":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl queue rm <id>")
		}
		if err := c.delete(ctx, "/api/v1/queue/"+rest[0], nil); err != nil {
			return err
		}
		note("Deleted. The body is gone from the spool.")
		return nil

	case "release":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl queue release <id>")
		}
		if err := c.post(ctx, "/api/v1/queue/"+rest[0]+"/release", nil, nil); err != nil {
			return err
		}
		note("Released from quarantine and queued for delivery.")
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q (try list, show, retry, rm, release)", sub)
	}
}

func cmdEvents(ctx context.Context, c *Client, args []string) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	limit := fs.Int("limit", 40, "how many to show")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var body struct {
		Events []struct {
			ID        int64          `json:"id"`
			Type      string         `json:"type"`
			QueueID   *string        `json:"queue_id"`
			Data      map[string]any `json:"data"`
			CreatedAt time.Time      `json:"created_at"`
		} `json:"events"`
	}
	if err := c.get(ctx, "/api/v1/events?limit="+strconv.Itoa(*limit), &body); err != nil {
		return err
	}
	if jsonOut {
		return emit(body.Events)
	}
	if len(body.Events) == 0 {
		note("Nothing on the timeline yet.")
		return nil
	}

	t := newTable("WHEN", "EVENT", "DETAIL")
	for _, e := range body.Events {
		created := e.CreatedAt
		t.row(ago(&created), e.Type, truncate(summarise(e.Data), 60))
	}
	t.flush()
	return nil
}

func summarise(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, data[k]))
	}
	return strings.Join(parts, " ")
}

func cmdFilters(ctx context.Context, c *Client, args []string) error {
	sub, _ := split(args, "list")
	if sub != "list" {
		return fmt.Errorf("unknown subcommand %q (only list is available here; "+
			"filters are edited in the UI, where the pattern can be tried before it is saved", sub)
	}

	var body struct {
		Filters []struct {
			ID         int64      `json:"id"`
			Name       string     `json:"name"`
			Field      string     `json:"field"`
			Pattern    string     `json:"pattern"`
			Action     string     `json:"action"`
			Enabled    bool       `json:"enabled"`
			Priority   int        `json:"priority"`
			MatchCount int64      `json:"match_count"`
			LastMatch  *time.Time `json:"last_match_at"`
		} `json:"filters"`
	}
	if err := c.get(ctx, "/api/v1/filters", &body); err != nil {
		return err
	}
	if jsonOut {
		return emit(body.Filters)
	}
	if len(body.Filters) == 0 {
		note("No filters configured.")
		return nil
	}

	t := newTable("ID", "PRIO", "NAME", "FIELD", "ACTION", "PATTERN", "MATCHES", "LAST")
	for _, f := range body.Filters {
		name := f.Name
		if !f.Enabled {
			name += " (off)"
		}
		t.row(strconv.FormatInt(f.ID, 10), strconv.Itoa(f.Priority), name,
			f.Field, f.Action, truncate(f.Pattern, 30),
			strconv.FormatInt(f.MatchCount, 10), ago(f.LastMatch))
	}
	t.flush()
	return nil
}

func cmdWebhooks(ctx context.Context, c *Client, args []string) error {
	sub, rest := split(args, "list")
	switch sub {
	case "list":
		var body struct {
			Enabled  bool `json:"enabled"`
			Webhooks []struct {
				ID        int64      `json:"id"`
				Name      string     `json:"name"`
				URL       string     `json:"url"`
				Events    []string   `json:"events"`
				Enabled   bool       `json:"enabled"`
				Signed    bool       `json:"signed"`
				LastError string     `json:"last_error"`
				LastOK    *time.Time `json:"last_success_at"`
			} `json:"webhooks"`
		}
		if err := c.get(ctx, "/api/v1/webhooks", &body); err != nil {
			return err
		}
		if jsonOut {
			return emit(body)
		}
		if !body.Enabled {
			warn("Event webhooks are switched off in the configuration; nothing here will be delivered.")
		}
		if len(body.Webhooks) == 0 {
			note("No subscriptions.")
			return nil
		}
		t := newTable("ID", "NAME", "URL", "EVENTS", "SIGNED", "LAST OK", "LAST ERROR")
		for _, h := range body.Webhooks {
			events := "all"
			if len(h.Events) > 0 {
				events = strconv.Itoa(len(h.Events))
			}
			name := h.Name
			if !h.Enabled {
				name += " (off)"
			}
			t.row(strconv.FormatInt(h.ID, 10), name, truncate(h.URL, 36), events,
				yesNo(h.Signed), ago(h.LastOK), truncate(h.LastError, 30))
		}
		t.flush()
		return nil

	case "test":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl webhooks test <id>")
		}
		var res struct {
			OK     bool   `json:"ok"`
			Status int    `json:"status"`
			Error  string `json:"error"`
		}
		if err := c.post(ctx, "/api/v1/webhooks/"+rest[0]+"/test", nil, &res); err != nil {
			return err
		}
		if jsonOut {
			return emit(res)
		}
		if res.OK {
			note("The endpoint answered %d.", res.Status)
			return nil
		}
		return fmt.Errorf("the endpoint did not accept the test: %s", res.Error)

	case "deliveries":
		fs := flag.NewFlagSet("webhooks deliveries", flag.ContinueOnError)
		hookID := fs.Int("webhook", 0, "only this subscription")
		limit := fs.Int("limit", 30, "how many to show")
		if err := fs.Parse(rest); err != nil {
			return err
		}

		q := url.Values{}
		q.Set("limit", strconv.Itoa(*limit))
		if *hookID > 0 {
			q.Set("webhook_id", strconv.Itoa(*hookID))
		}

		var body struct {
			Deliveries []struct {
				ID          int64      `json:"id"`
				WebhookName string     `json:"webhook_name"`
				Event       string     `json:"event"`
				Status      string     `json:"status"`
				Attempts    int        `json:"attempts"`
				StatusCode  int        `json:"status_code"`
				LastError   string     `json:"last_error"`
				CreatedAt   time.Time  `json:"created_at"`
				NextAttempt *time.Time `json:"next_attempt_at"`
			} `json:"deliveries"`
		}
		if err := c.get(ctx, "/api/v1/webhooks/deliveries?"+q.Encode(), &body); err != nil {
			return err
		}
		if jsonOut {
			return emit(body.Deliveries)
		}
		if len(body.Deliveries) == 0 {
			note("Nothing has been delivered yet.")
			return nil
		}
		t := newTable("ID", "SUBSCRIPTION", "EVENT", "STATUS", "TRIES", "CODE", "WHEN", "DETAIL")
		for _, d := range body.Deliveries {
			created := d.CreatedAt
			detail := d.LastError
			if d.Status == "pending" && d.NextAttempt != nil {
				detail = "retry " + until(d.NextAttempt)
			}
			code := ""
			if d.StatusCode > 0 {
				code = strconv.Itoa(d.StatusCode)
			}
			t.row(strconv.FormatInt(d.ID, 10), truncate(d.WebhookName, 16), d.Event,
				d.Status, strconv.Itoa(d.Attempts), code, ago(&created), truncate(detail, 34))
		}
		t.flush()
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q (try list, test, deliveries)", sub)
	}
}

func cmdTokens(ctx context.Context, c *Client, args []string) error {
	sub, rest := split(args, "list")
	switch sub {
	case "list":
		var body struct {
			Tokens []struct {
				ID       int64      `json:"id"`
				Name     string     `json:"name"`
				Prefix   string     `json:"prefix"`
				Role     string     `json:"role"`
				Expires  *time.Time `json:"expires_at"`
				LastUsed *time.Time `json:"last_used_at"`
				Expired  bool       `json:"expired"`
			} `json:"tokens"`
		}
		if err := c.get(ctx, "/api/v1/tokens", &body); err != nil {
			return err
		}
		if jsonOut {
			return emit(body.Tokens)
		}
		if len(body.Tokens) == 0 {
			note("No API tokens.")
			return nil
		}
		t := newTable("ID", "NAME", "PREFIX", "ROLE", "EXPIRES", "LAST USED")
		for _, tok := range body.Tokens {
			name := tok.Name
			if tok.Expired {
				name += " (expired)"
			}
			t.row(strconv.FormatInt(tok.ID, 10), name, tok.Prefix+"…",
				tok.Role, until(tok.Expires), ago(tok.LastUsed))
		}
		t.flush()
		return nil

	case "rm":
		if len(rest) != 1 {
			return errors.New("usage: xeronmxctl tokens rm <id>")
		}
		if err := c.delete(ctx, "/api/v1/tokens/"+rest[0], nil); err != nil {
			return err
		}
		note("Revoked. Anything using it stops working now.")
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q (try list, rm. "+
			"New tokens are created in the UI, which is the only place the secret is ever shown", sub)
	}
}

func cmdCluster(ctx context.Context, c *Client) error {
	var body struct {
		Enabled       bool   `json:"enabled"`
		NodeID        string `json:"node_id"`
		Role          string `json:"role"`
		HealthyAfter  int    `json:"healthy_after"`
		Drifted       int    `json:"drifted"`
		QueueIsShared bool   `json:"queue_is_shared"`
		Nodes         []struct {
			ID           string    `json:"node_id"`
			AdvertiseURL string    `json:"advertise_url"`
			Version      string    `json:"version"`
			Role         string    `json:"role"`
			ConfigHash   string    `json:"config_hash"`
			QueuePending int64     `json:"queue_pending"`
			QueueBytes   int64     `json:"queue_bytes"`
			Domains      int64     `json:"domains"`
			LastSeen     time.Time `json:"last_seen"`
			Healthy      bool      `json:"healthy"`
			Self         bool      `json:"self"`
			ConfigDrift  bool      `json:"config_drift"`
		} `json:"nodes"`
	}
	if err := c.get(ctx, "/api/v1/cluster", &body); err != nil {
		return err
	}
	if jsonOut {
		return emit(body)
	}
	if !body.Enabled {
		note("Clustering is off. This node runs alone.")
		return nil
	}

	note("This node: %s (%s)", body.NodeID, body.Role)
	note("")

	t := newTable("NODE", "ROLE", "STATE", "PENDING", "DOMAINS", "CONFIG", "VERSION", "SEEN")
	for _, n := range body.Nodes {
		state := "down"
		if n.Healthy {
			state = "up"
		}
		name := n.ID
		if n.Self {
			name += " *"
		}
		conf := truncate(n.ConfigHash, 12)
		if n.ConfigDrift {
			conf += " DRIFT"
		}
		if n.ConfigHash == "" {
			conf = "unknown"
		}
		seen := n.LastSeen
		t.row(name, n.Role, state,
			fmt.Sprintf("%d (%s)", n.QueuePending, bytesHuman(n.QueueBytes)),
			strconv.FormatInt(n.Domains, 10), conf, n.Version, ago(&seen))
	}
	t.flush()
	note("")

	if body.Drifted > 0 {
		warn("%d node(s) are configured differently from this one. A domain that exists", body.Drifted)
		warn("on one node and not the other means half the internet gets a 550.")
	}
	if !body.QueueIsShared {
		note("Each node holds its own spool. Nothing here is replicated mail:")
		note("a node that is down is drained by itself when it comes back.")
	}
	return nil
}

func cmdConfig(ctx context.Context, c *Client, args []string) error {
	sub, rest := split(args, "")
	switch sub {
	case "export":
		var raw []byte
		if err := c.get(ctx, "/api/v1/config", &raw); err != nil {
			return err
		}
		if len(rest) == 1 {
			if err := os.WriteFile(rest[0], raw, 0o600); err != nil {
				return err
			}
			note("Written to %s", rest[0])
			return nil
		}
		return writeOut(os.Stdout, raw)

	case "import":
		fs := flag.NewFlagSet("config import", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "report what would change without changing it")
		args, err := parseMixed(fs, rest)
		if err != nil {
			return err
		}
		if len(args) != 1 {
			return errors.New("usage: xeronmxctl config import <file.yaml> [--dry-run]")
		}
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}

		path := "/api/v1/config"
		if *dryRun {
			path += "?dry_run=true"
		}
		var report struct {
			DryRun      bool     `json:"dry_run"`
			Description string   `json:"description"`
			Warnings    []string `json:"warnings"`
			Domains     []struct {
				Name   string `json:"name"`
				Action string `json:"action"`
			} `json:"domains"`
			SMTPUsers []struct {
				Name   string `json:"name"`
				Action string `json:"action"`
			} `json:"smtp_users"`
		}
		if err := c.postRaw(ctx, path, "application/yaml", raw, &report); err != nil {
			return err
		}
		if jsonOut {
			return emit(report)
		}

		if report.DryRun {
			note("Dry run: nothing was changed.")
		}
		t := newTable("KIND", "NAME", "ACTION")
		for _, d := range report.Domains {
			t.row("domain", d.Name, d.Action)
		}
		for _, u := range report.SMTPUsers {
			t.row("account", u.Name, u.Action)
		}
		t.flush()
		note("")
		note("%s", report.Description)
		for _, w := range report.Warnings {
			warn("warning: %s", w)
		}
		return nil

	default:
		return errors.New("usage: xeronmxctl config export [file] | import <file> [--dry-run]")
	}
}

func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i:]...)
			break
		}
		positional = append(positional, args[i])
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return append(positional, fs.Args()...), nil
}

func split(args []string, fallback string) (string, []string) {
	if len(args) == 0 {
		return fallback, nil
	}
	return args[0], args[1:]
}

func cmdDrain(ctx context.Context, c *Client, args []string) error {
	fs := flag.NewFlagSet("drain", flag.ContinueOnError)
	statusFlag := fs.Bool("status", false, "display drain status without modifying it")
	cancelFlag := fs.Bool("cancel", false, "disable drain mode (resume accepting inbound mail)")
	disableFlag := fs.Bool("disable", false, "disable drain mode (resume accepting inbound mail)")
	waitFlag := fs.Bool("wait", false, "wait until all queued messages have drained")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type drainResp struct {
		Draining     bool  `json:"draining"`
		Pending      int64 `json:"pending"`
		PendingBytes int64 `json:"pending_bytes"`
	}

	var res drainResp
	if *statusFlag {
		if err := c.get(ctx, "/api/v1/maintenance/drain", &res); err != nil {
			return err
		}
	} else {
		enable := !(*cancelFlag || *disableFlag)
		if err := c.post(ctx, "/api/v1/maintenance/drain", map[string]any{"enabled": enable}, &res); err != nil {
			return err
		}
	}

	if jsonOut {
		return emit(res)
	}

	if *statusFlag {
		if res.Draining {
			note("Drain mode: ACTIVE (refusing new inbound mail with 421)")
		} else {
			note("Drain mode: INACTIVE (normal operation)")
		}
		note("Spool depth: %d pending messages (%s)", res.Pending, bytesHuman(res.PendingBytes))
		return nil
	}

	if res.Draining {
		note("Drain mode enabled. New inbound SMTP connections are refused with 421.")
		note("Spool depth: %d pending messages (%s)", res.Pending, bytesHuman(res.PendingBytes))
		if *waitFlag {
			note("Waiting for queue to drain to 0 messages...")
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					if err := c.get(ctx, "/api/v1/maintenance/drain", &res); err != nil {
						return err
					}
					if res.Pending == 0 {
						note("Spool is completely drained (0 messages). Safe to perform maintenance or restart.")
						return nil
					}
					note("... %d messages remaining (%s)", res.Pending, bytesHuman(res.PendingBytes))
				}
			}
		}
	} else {
		note("Drain mode disabled. Normal SMTP intake resumed.")
	}
	return nil
}
