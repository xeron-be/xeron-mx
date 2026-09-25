package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const configDocVersion = 1

const maxConfigBytes = 1 << 20

type configDocument struct {
	Version   int              `yaml:"version"`
	Domains   []configDomain   `yaml:"domains,omitempty"`
	SMTPUsers []configSMTPUser `yaml:"smtp_users,omitempty"`
}

type configDomain struct {
	Name             string `yaml:"name"`
	PrimaryHost      string `yaml:"primary_host"`
	PrimaryPort      int    `yaml:"primary_port,omitempty"`
	PrimaryTLS       string `yaml:"primary_tls,omitempty"`
	MaxQueueMessages *int64 `yaml:"max_queue_messages,omitempty"`
	MonthlySendLimit *int64 `yaml:"monthly_send_limit,omitempty"`
	RetentionHours   int    `yaml:"retention_hours,omitempty"`
	Enabled          *bool  `yaml:"enabled,omitempty"`

	Recipients *[]string `yaml:"recipients,omitempty"`
}

type configSMTPUser struct {
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password,omitempty"`
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`
	Enabled        *bool    `yaml:"enabled,omitempty"`
}

type changed struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	body, err := s.ExportConfigYAML(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrConfigExportFailed)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="xeronmx-config.yaml"`)
	w.Write(body)
}

func (s *Server) ExportConfigYAML(ctx context.Context) ([]byte, error) {
	domains, err := s.db.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("read domains: %w", err)
	}
	users, err := s.db.ListSMTPUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("read submission accounts: %w", err)
	}

	doc := configDocument{Version: configDocVersion}
	for _, d := range domains {
		enabled := d.Enabled
		cd := configDomain{
			Name:             d.Name,
			PrimaryHost:      d.PrimaryHost,
			PrimaryPort:      d.PrimaryPort,
			PrimaryTLS:       d.PrimaryTLS,
			MaxQueueMessages: d.MaxQueueMessages,
			MonthlySendLimit: d.MonthlySendLimit,
			RetentionHours:   d.RetentionHours,
			Enabled:          &enabled,
		}
		list, err := s.db.DomainRecipients(ctx, d.ID)
		if err != nil {
			return nil, fmt.Errorf("read recipients of %s: %w", d.Name, err)
		}
		if len(list) > 0 {
			cd.Recipients = &list
		}
		doc.Domains = append(doc.Domains, cd)
	}
	for _, u := range users {
		enabled := u.Enabled
		doc.SMTPUsers = append(doc.SMTPUsers, configSMTPUser{
			Username:       u.Username,
			AllowedDomains: u.AllowedDomains,
			Enabled:        &enabled,
		})
	}

	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("render configuration: %w", err)
	}

	preamble := "# XeronMX configuration export.\n" +
		"#\n" +
		"# Submission passwords are not here and cannot be: only their Argon2id hash is\n" +
		"# stored. Add a `password:` to an account in this file to create it elsewhere.\n" +
		"#\n" +
		"# Importing this creates what is missing and updates what differs. It never\n" +
		"# deletes: removing a domain destroys the mail queued for it, which stays a\n" +
		"# deliberate single action.\n\n"

	return append([]byte(preamble), body...), nil
}

func (s *Server) ConfigHash(ctx context.Context) (string, error) {
	body, err := s.ExportConfigYAML(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:12]), nil
}

func (s *Server) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dryRun := r.URL.Query().Get("dry_run") == "true"

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfigBytes))
	if err != nil {
		s.fail(w, r, http.StatusRequestEntityTooLarge, ErrRequestTooLarge)
		return
	}

	report, err := s.ApplyConfigYAML(ctx, raw, dryRun)
	switch {
	case errors.Is(err, errBadConfigDocument):
		s.fail(w, r, http.StatusBadRequest, ErrInvalidConfig)
		return
	case err != nil:
		s.log.Error("config import failed midway", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrConfigImportFailed)
		return
	}

	if !dryRun {
		admin := userFrom(r)
		s.log.Warn("configuration imported", "by", admin.Email, "summary", report["description"])
		s.audit(ctx, r, &store.Event{
			Type: "config_imported", UserID: &admin.ID,
			Data: map[string]any{"summary": report["description"]},
		})
	}
	s.ok(w, http.StatusOK, report)
}

var errBadConfigDocument = errors.New("invalid configuration document")

func (s *Server) ApplyConfigYAML(ctx context.Context, raw []byte, dryRun bool) (map[string]any, error) {
	var doc configDocument
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: could not parse the YAML: %s", errBadConfigDocument, err.Error())
	}
	if doc.Version != 0 && doc.Version != configDocVersion {
		return nil, fmt.Errorf("%w: this document is version %d, which this build does not understand",
			errBadConfigDocument, doc.Version)
	}

	plan, warnings, errMsg := s.planImport(ctx, &doc)
	if errMsg != "" {
		return nil, fmt.Errorf("%w: %s", errBadConfigDocument, errMsg)
	}

	report := map[string]any{
		"dry_run":     dryRun,
		"domains":     plan.domains,
		"smtp_users":  plan.users,
		"warnings":    warnings,
		"description": plan.summary(),
		"changed":     plan.changedCount(),
	}
	if dryRun {
		return report, nil
	}
	if err := s.applyImport(ctx, plan); err != nil {
		return nil, err
	}
	return report, nil
}

type importPlan struct {
	domains []changed
	users   []changed

	createDomains []*store.Domain
	updateDomains []*store.Domain
	createUsers   []configSMTPUser
	enableUsers   map[string]bool
	setRecipients map[string][]string
}

func (p *importPlan) summary() string {
	var created, updated int
	for _, c := range append(append([]changed{}, p.domains...), p.users...) {
		switch c.Action {
		case "created":
			created++
		case "updated":
			updated++
		}
	}
	return fmt.Sprintf("%d created, %d updated, %d unchanged",
		created, updated, len(p.domains)+len(p.users)-created-updated)
}

func (p *importPlan) changedCount() int {
	var n int
	for _, c := range append(append([]changed{}, p.domains...), p.users...) {
		if c.Action == "created" || c.Action == "updated" {
			n++
		}
	}
	return n
}

func (s *Server) planImport(ctx context.Context, doc *configDocument) (*importPlan, []string, string) {
	plan := &importPlan{enableUsers: map[string]bool{}, setRecipients: map[string][]string{}}
	var warnings []string

	incoming := map[string]bool{}
	for _, cd := range doc.Domains {
		name := strings.ToLower(strings.TrimSpace(cd.Name))
		if name == "" {
			return nil, nil, "every domain needs a name"
		}
		if incoming[name] {
			return nil, nil, fmt.Sprintf("%q is listed twice", name)
		}
		incoming[name] = true

		existing, err := s.db.DomainByName(ctx, name)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, nil, "could not read the existing domains"
		}
		if errors.Is(err, store.ErrNotFound) {
			existing = nil
		}

		req := &domainRequest{
			Name:             cd.Name,
			PrimaryHost:      cd.PrimaryHost,
			PrimaryPort:      cd.PrimaryPort,
			PrimaryTLS:       cd.PrimaryTLS,
			MaxQueueMessages: cd.MaxQueueMessages,
			MonthlySendLimit: cd.MonthlySendLimit,
			RetentionHours:   cd.RetentionHours,
			Enabled:          cd.Enabled,
		}
		d, errMsg := s.domainFromRequest(req, existing)
		if errMsg != "" {
			return nil, nil, fmt.Sprintf("%s: %s", name, errMsg)
		}

		recipientsChange := false
		if cd.Recipients != nil {
			list, valid := validRecipients(name, *cd.Recipients)
			if !valid {
				return nil, nil, fmt.Sprintf("%s: every known recipient must be an address in %s", name, name)
			}
			current := []string{}
			if existing != nil {
				if current, err = s.db.DomainRecipients(ctx, existing.ID); err != nil {
					return nil, nil, "could not read the existing recipient lists"
				}
			}
			if !slices.Equal(current, list) {
				recipientsChange = true
				plan.setRecipients[name] = list
			}
		}

		switch {
		case existing == nil:
			plan.createDomains = append(plan.createDomains, d)
			plan.domains = append(plan.domains, changed{Name: name, Action: "created"})
		case sameDomain(existing, d) && !recipientsChange:
			plan.domains = append(plan.domains, changed{Name: name, Action: "unchanged"})
		default:
			plan.updateDomains = append(plan.updateDomains, d)
			plan.domains = append(plan.domains, changed{Name: name, Action: "updated"})
		}
	}

	seenUser := map[string]bool{}
	for _, cu := range doc.SMTPUsers {
		username := strings.TrimSpace(cu.Username)
		if username == "" {
			return nil, nil, "every submission account needs a username"
		}
		if strings.ContainsAny(username, " \t\r\n") {
			return nil, nil, fmt.Sprintf("%q is not a valid username", username)
		}
		if seenUser[username] {
			return nil, nil, fmt.Sprintf("%q is listed twice", username)
		}
		seenUser[username] = true

		for _, ad := range cu.AllowedDomains {
			name := strings.ToLower(strings.TrimSpace(ad))
			if incoming[name] {
				continue
			}
			if _, err := s.db.DomainByName(ctx, name); err != nil {
				return nil, nil, fmt.Sprintf("%s allows sending as %q, which is not a configured domain "+
					"and is not in this document either", username, ad)
			}
		}

		existing, err := s.db.SMTPUserByName(ctx, username)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, nil, "could not read the existing submission accounts"
		}

		if errors.Is(err, store.ErrNotFound) {
			if cu.Password == "" {
				warnings = append(warnings, fmt.Sprintf(
					"%s was skipped: it does not exist yet and the document carries no password for it", username))
				plan.users = append(plan.users, changed{Name: username, Action: "skipped"})
				continue
			}
			if err := auth.ValidatePassword(cu.Password); err != nil {
				return nil, nil, fmt.Sprintf("%s: %s", username, err.Error())
			}
			plan.createUsers = append(plan.createUsers, cu)
			plan.users = append(plan.users, changed{Name: username, Action: "created"})
			continue
		}

		if cu.Password != "" {
			warnings = append(warnings, fmt.Sprintf(
				"%s already exists, so its password was left alone; delete and recreate it to change one", username))
		}
		if cu.Enabled != nil && *cu.Enabled != existing.Enabled {
			plan.enableUsers[username] = *cu.Enabled
			plan.users = append(plan.users, changed{Name: username, Action: "updated"})
			continue
		}
		plan.users = append(plan.users, changed{Name: username, Action: "unchanged"})
	}

	return plan, warnings, ""
}

func (s *Server) applyImport(ctx context.Context, plan *importPlan) error {
	for _, d := range plan.createDomains {
		if _, err := s.db.CreateDomain(ctx, d); err != nil {
			return fmt.Errorf("create domain %s: %w", d.Name, err)
		}
	}
	for _, d := range plan.updateDomains {
		if err := s.db.UpdateDomain(ctx, d); err != nil {
			return fmt.Errorf("update domain %s: %w", d.Name, err)
		}
	}
	for name, list := range plan.setRecipients {
		d, err := s.db.DomainByName(ctx, name)
		if err != nil {
			return fmt.Errorf("look up %s: %w", name, err)
		}
		if err := s.db.SetDomainRecipients(ctx, d.ID, list); err != nil {
			return fmt.Errorf("set recipients of %s: %w", name, err)
		}
	}
	for _, cu := range plan.createUsers {
		hash, err := auth.HashPassword(cu.Password)
		if err != nil {
			return fmt.Errorf("hash password for %s: %w", cu.Username, err)
		}
		if _, err := s.db.CreateSMTPUser(ctx, cu.Username, hash, cu.AllowedDomains); err != nil {
			return fmt.Errorf("create submission account %s: %w", cu.Username, err)
		}
	}
	for username, enabled := range plan.enableUsers {
		u, err := s.db.SMTPUserByName(ctx, username)
		if err != nil {
			return fmt.Errorf("look up %s: %w", username, err)
		}
		if err := s.db.SetSMTPUserEnabled(ctx, u.ID, enabled); err != nil {
			return fmt.Errorf("update %s: %w", username, err)
		}
	}
	return nil
}

func sameDomain(a, b *store.Domain) bool {
	if a.PrimaryHost != b.PrimaryHost || a.PrimaryPort != b.PrimaryPort ||
		a.PrimaryTLS != b.PrimaryTLS || a.RetentionHours != b.RetentionHours ||
		a.Enabled != b.Enabled {
		return false
	}
	return sameLimit(a.MaxQueueMessages, b.MaxQueueMessages) &&
		sameLimit(a.MonthlySendLimit, b.MonthlySendLimit)
}

func sameLimit(a, b *int64) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}
