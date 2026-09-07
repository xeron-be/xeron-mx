package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/dkim"
	"github.com/xeron-be/xeron-mx/internal/dmarc"
	"github.com/xeron-be/xeron-mx/internal/health"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/version"
)

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.db.CountUsers(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	s.ok(w, http.StatusOK, map[string]any{
		"needs_setup":    n == 0,
		"version":        version.Version,
		"password_login": s.passwordLoginAllowed(),
		"oidc":           s.oidcAdvertisement(),
	})
}

func (s *Server) oidcAdvertisement() map[string]any {
	if s.oidc == nil || !s.oidc.Enabled() {
		return map[string]any{"enabled": false}
	}
	ready, _ := s.oidc.Ready()
	return map[string]any{"enabled": true, "ready": ready}
}

func (s *Server) passwordLoginAllowed() bool {
	if s.oidc == nil || !s.oidc.Enabled() {
		return true
	}
	return s.oidc.AllowPasswordLogin()
}

type setupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.db.CountUsers(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	if n > 0 {
		s.fail(w, r, http.StatusConflict, ErrAlreadySetup)
		return
	}

	var req setupRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if !isEmail(req.Email) {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidEmail)
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidPassword)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrUserCreationFailed)
		return
	}

	userID, err := s.db.CreateFirstUser(r.Context(), req.Email, hash, store.RoleAdmin)
	if err != nil {
		if !errors.Is(err, store.ErrAlreadySetUp) {
			s.log.Error("setup: create user failed", "error", err)
		}
		s.fail(w, r, http.StatusConflict, ErrAlreadySetup)
		return
	}

	s.log.Info("initial administrator created", "email", req.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventLogin, UserID: &userID,
		Data: map[string]any{"initial_setup": true},
	})

	if err := s.startSession(w, r, userID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrSessionCreationFailed)
		return
	}
	s.ok(w, http.StatusCreated, map[string]any{"id": userID, "email": req.Email, "role": store.RoleAdmin})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.passwordLoginAllowed() {
		s.fail(w, r, http.StatusForbidden, ErrPasswordLoginDisabled)
		return
	}

	ip := clientIP(r)
	if !s.limiter.Allow(ip) {
		s.log.Warn("login rate limit hit", "ip", ip)
		s.fail(w, r, http.StatusTooManyRequests, ErrRateLimited)
		return
	}

	var req loginRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if len(req.Password) > auth.MaxPasswordBytes {

		s.loginFailed(w, r, req.Email, ip)
		return
	}

	user, err := s.db.UserByEmail(r.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("login: user lookup failed", "error", err)
		}

		auth.HashPassword(req.Password)
		s.loginFailed(w, r, req.Email, ip)
		return
	}

	if !user.HasPassword() {
		s.loginFailed(w, r, req.Email, ip)
		return
	}

	valid, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		if err != nil {
			s.log.Error("login: hash verification failed", "error", err)
		}
		s.loginFailed(w, r, req.Email, ip)
		return
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("login: session creation failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSessionCreationFailed)
		return
	}

	s.limiter.Reset(ip)

	s.db.TouchLogin(r.Context(), user.ID)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventLogin, UserID: &user.ID, Data: map[string]any{"ip": ip},
	})
	s.log.Info("login", "email", user.Email, "ip", ip)

	s.ok(w, http.StatusOK, map[string]any{
		"id": user.ID, "email": user.Email, "role": user.Role,
		"allowed_domains": user.AllowedDomains,
	})
}

func (s *Server) loginFailed(w http.ResponseWriter, r *http.Request, email, ip string) {
	s.log.Warn("failed login", "email", email, "ip", ip)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventLoginFailed,
		Data: map[string]any{"email": email, "ip": ip},
	})
	s.fail(w, r, http.StatusUnauthorized, ErrInvalidCredentials)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	token, hash, err := auth.NewSessionToken()
	if err != nil {
		return err
	}
	ttl := s.cfg.SessionTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	if err := s.db.CreateSession(r.Context(), hash, userID, ttl, r.UserAgent()); err != nil {
		return err
	}
	s.setSessionCookie(w, token, ttl)
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.db.DeleteSession(r.Context(), auth.HashToken(cookie.Value))
	}
	s.clearSessionCookie(w)
	s.ok(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	body := map[string]any{
		"id": u.ID, "email": u.Email, "role": u.Role,
		"allowed_domains": u.AllowedDomains,
		"created_at":      u.CreatedAt, "last_login_at": u.LastLoginAt,
		"from_directory": u.FromDirectory(),
		"has_password":   u.HasPassword(),
	}
	if tok := tokenFrom(r); tok != nil {
		body["via_token"] = map[string]any{
			"id": tok.ID, "name": tok.Name, "role": tok.Role, "expires_at": tok.ExpiresAt,
		}
	}
	s.ok(w, http.StatusOK, body)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(r)

	type domainStatus struct {
		ID       int64      `json:"id"`
		Name     string     `json:"name"`
		Enabled  bool       `json:"enabled"`
		IsUp     bool       `json:"is_up"`
		Since    *time.Time `json:"since,omitempty"`
		Pending  int64      `json:"pending"`
		LastErr  string     `json:"last_error,omitempty"`
		LastSeen *time.Time `json:"last_check,omitempty"`
	}

	domains, err := s.domainsForUser(ctx, u)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDomainListFailed)
		return
	}

	allowedIDs, err := s.allowedDomainIDsForUser(ctx, u)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	var stats store.QueueStats
	var quarantined int64
	if allowedIDs != nil {
		stats, err = s.db.StatsForDomains(ctx, allowedIDs)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrInternal)
			return
		}
		quarantined, err = s.db.CountQuarantinedForDomains(ctx, allowedIDs)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrInternal)
			return
		}
	} else {
		stats, err = s.db.Stats(ctx)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrInternal)
			return
		}
		quarantined, err = s.db.CountQuarantined(ctx)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrInternal)
			return
		}
	}

	out := make([]domainStatus, 0, len(domains))
	allUp := true
	for _, d := range domains {
		ds := domainStatus{ID: d.ID, Name: d.Name, Enabled: d.Enabled}
		if st, err := s.db.PrimaryStatusFor(ctx, d.ID); err == nil {
			ds.IsUp, ds.LastErr, ds.LastSeen = st.IsUp, st.LastError, st.LastCheck
			if st.IsUp {
				ds.Since = st.LastUp
			} else {
				ds.Since = st.LastDown
			}
		}
		if n, err := s.db.CountPendingForDomain(ctx, d.ID); err == nil {
			ds.Pending = n
		}
		if d.Enabled && !ds.IsUp {
			allUp = false
		}
		out = append(out, ds)
	}

	isDraining := false
	if s.maintenance != nil {
		isDraining = s.maintenance.IsDraining()
	}

	body := map[string]any{
		"version":  version.Version,
		"commit":   version.Commit,
		"draining": isDraining,
		"queue": map[string]any{
			"pending":       stats.Pending,
			"pending_bytes": stats.PendingBytes,
			"total":         stats.Total,
			"max_messages":  s.queue.MaxMessages,
			"max_bytes":     s.queue.MaxBytes,
			"retention":     s.queue.Retention.String(),
		},
		"domains":             out,
		"all_primaries_up":    allUp,
		"quarantined":         quarantined,
		"dashboards_watching": s.hub.clientCount(),
	}
	if s.minDisk > 0 && s.diskCheck != nil && s.diskPath != "" {
		avail, err := s.diskCheck(s.diskPath)
		diskInfo := map[string]any{
			"min_free_bytes": s.minDisk,
			"guard_enabled":  true,
		}
		if err == nil {
			diskInfo["available_bytes"] = avail
			diskInfo["is_low"] = avail < uint64(s.minDisk)
		}
		body["disk"] = diskInfo
	}
	if s.certs != nil {
		st := s.certs.CertificateState()
		tlsInfo := map[string]any{
			"source": st.Source,
			"domain": st.Domain,
			"since":  st.Since,
		}
		if st.LastError != "" {
			tlsInfo["last_error"] = st.LastError
		}
		body["tls"] = tlsInfo
	}
	s.ok(w, http.StatusOK, body)
}

type drainRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleGetDrain(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.Stats(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	isDraining := false
	if s.maintenance != nil {
		isDraining = s.maintenance.IsDraining()
	}
	s.ok(w, http.StatusOK, map[string]any{
		"draining":      isDraining,
		"pending":       stats.Pending,
		"pending_bytes": stats.PendingBytes,
	})
}

func (s *Server) handleSetDrain(w http.ResponseWriter, r *http.Request) {
	enabled := true
	if r.Body != nil && r.ContentLength > 0 {
		var req drainRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Enabled != nil {
			enabled = *req.Enabled
		}
	}
	if s.maintenance != nil {
		s.maintenance.SetDraining(enabled)
	}

	u := userFrom(r)
	userEmail := ""
	if u != nil {
		userEmail = u.Email
	}
	_ = s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventMaintenanceDrain,
		Data: map[string]any{
			"enabled": enabled,
			"user":    userEmail,
		},
	})
	s.hub.Notify("maintenance", map[string]any{
		"draining": enabled,
	})
	s.handleGetDrain(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {

	s.ok(w, http.StatusOK, map[string]string{"status": "ok", "version": version.Version})
}

type domainRequest struct {
	Name             string `json:"name"`
	PrimaryHost      string `json:"primary_host"`
	PrimaryPort      int    `json:"primary_port"`
	PrimaryTLS       string `json:"primary_tls"`
	MaxQueueMessages *int64 `json:"max_queue_messages"`
	RetentionHours   int    `json:"retention_hours"`
	Enabled          *bool  `json:"enabled"`
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.domainsForUser(r.Context(), userFrom(r))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDomainListFailed)
		return
	}
	out := make([]map[string]any, 0, len(domains))
	for _, d := range domains {
		out = append(out, s.domainJSON(r.Context(), d))
	}
	s.ok(w, http.StatusOK, map[string]any{"domains": out})
}

func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	s.ok(w, http.StatusOK, s.domainJSON(r.Context(), d))
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req domainRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	d, errMsg := s.domainFromRequest(&req, nil)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}

	id, err := s.db.CreateDomain(r.Context(), d)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			s.fail(w, r, http.StatusConflict, ErrDomainExists)
			return
		}
		s.log.Error("create domain failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrDomainCreateFailed)
		return
	}
	d.ID = id

	if stored, err := s.db.DomainByID(r.Context(), id); err == nil {
		d = stored
	}

	s.log.Info("domain added", "name", d.Name, "primary", d.PrimaryHost)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "domain_added", DomainID: &id, UserID: &userFrom(r).ID,
		Data: map[string]any{"name": d.Name, "primary_host": d.PrimaryHost},
	})
	s.ok(w, http.StatusCreated, s.domainJSON(r.Context(), d))
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	var req domainRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	d, errMsg := s.domainFromRequest(&req, existing)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}
	if err := s.db.UpdateDomain(r.Context(), d); err != nil {
		s.log.Error("update domain failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrDomainUpdateFailed)
		return
	}
	s.ok(w, http.StatusOK, s.domainJSON(r.Context(), d))
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	pending, err := s.db.CountPendingForDomain(ctx, d.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	if pending > 0 && r.URL.Query().Get("force") != "true" {
		s.fail(w, r, http.StatusConflict, ErrDomainHasQueuedMail)
		return
	}

	msgs, err := s.db.ListMessages(ctx, store.ListFilter{DomainID: d.ID, Limit: 500})
	if err == nil {
		for _, m := range msgs {
			s.blobs.Delete(m.ID)
		}
	}
	if err := s.db.DeleteDomain(ctx, d.ID); err != nil {
		s.log.Error("delete domain failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrDomainDeleteFailed)
		return
	}

	s.log.Warn("domain deleted", "name", d.Name, "discarded_messages", pending)
	s.db.RecordEvent(ctx, &store.Event{
		Type: "domain_deleted", UserID: &userFrom(r).ID,
		Data: map[string]any{"name": d.Name, "discarded": pending},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": d.Name, "discarded_messages": pending})
}

func (s *Server) handleTestDomain(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	start := time.Now()
	err := health.Probe(ctx, d, 15*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		s.ok(w, http.StatusOK, map[string]any{
			"reachable": false,
			"error":     err.Error(),
			"took_ms":   elapsed.Milliseconds(),
			"hint":      probeHint(err),
		})
		return
	}
	s.ok(w, http.StatusOK, map[string]any{
		"reachable": true,
		"took_ms":   elapsed.Milliseconds(),
	})
}

func probeHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such host"):
		return "The hostname does not resolve. Check the primary host spelling and its DNS record."
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"),
		strings.Contains(msg, "econnrefused"):
		return "The host answered but nothing is listening on that port. Check the port, and that the mail server is running."
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "No answer at all. A firewall is the usual cause — port 25 is blocked outbound by many hosting providers."
	case strings.Contains(msg, "starttls"):
		return "The connection worked but TLS did not. Try the 'opportunistic' TLS mode, or check the certificate on the primary."
	case strings.Contains(msg, "certificate"):
		return "TLS failed on the certificate. Check that it is valid and matches the primary hostname."
	default:
		return "Check that the primary host and port are correct and reachable from this machine."
	}
}

func (s *Server) handleDomainDNS(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}

	mxHost := s.smtp.Hostname
	if mxHost == "" {
		mxHost = "mx2." + d.Name
	}

	records := []map[string]string{
		{
			"type":     "MX",
			"name":     d.Name + ".",
			"value":    mxHost + ".",
			"priority": "20",
			"note":     "Higher number than your primary MX, so senders only fall back here when the primary does not answer.",
		},
		{
			"type":  "A",
			"name":  mxHost + ".",
			"value": "<this server's public IPv4>",
			"note":  "Must point at the machine running XeronMX.",
		},
	}

	if k, err := s.db.DKIMKeyFor(r.Context(), d.ID); err == nil && k != nil {
		records = append(records, map[string]string{
			"type":  "TXT",
			"name":  dkim.RecordName(k.Selector, d.Name),
			"value": dkim.RecordValue(k.Algorithm, k.PublicKey),
			"note":  "DKIM public key for outbound email authentication.",
		})
	}

	records = append(records, map[string]string{
		"type":  "TXT",
		"name":  dmarc.RecordName(d.Name),
		"value": dmarc.DefaultValue(d.Name, "quarantine"),
		"note":  "DMARC policy for domain authentication and anti-spoofing.",
	})

	s.ok(w, http.StatusOK, map[string]any{
		"records": records,
		"checklist": []string{
			"The primary MX record for " + d.Name + " keeps a lower priority number than 20.",
			"Port 25 is reachable from the internet on this machine — many providers block it by default and will unblock on request.",
			"The reverse DNS (PTR) of this server's IP resolves to " + mxHost + ", or strict senders will refuse to talk to it.",
			"smtp.hostname in the configuration is set to " + mxHost + ".",
			"A DMARC TXT record is published at _dmarc." + d.Name + " to guarantee deliverability on Gmail and Outlook.",
		},
	})
}

func (s *Server) lookupDomain(w http.ResponseWriter, r *http.Request) (*store.Domain, bool) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidDomainID)
		return nil, false
	}
	d, err := s.db.DomainByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, ErrDomainNotFound)
		return nil, false
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDomainReadFailed)
		return nil, false
	}
	u := userFrom(r)
	if u != nil && !u.CanAccessDomain(d.Name) {
		s.fail(w, r, http.StatusNotFound, ErrDomainNotFound)
		return nil, false
	}
	return d, true
}

func (s *Server) domainFromRequest(req *domainRequest, existing *store.Domain) (*store.Domain, string) {
	d := &store.Domain{
		PrimaryPort:    25,
		PrimaryTLS:     smtpclient.TLSOpportunistic,
		RetentionHours: int(s.queue.Retention.Hours()),
		Enabled:        true,
	}
	if existing != nil {
		d = &store.Domain{
			ID: existing.ID, Name: existing.Name,
			PrimaryHost: existing.PrimaryHost, PrimaryPort: existing.PrimaryPort,
			PrimaryTLS: existing.PrimaryTLS, MaxQueueMessages: existing.MaxQueueMessages,
			RetentionHours: existing.RetentionHours, Enabled: existing.Enabled,
		}
	}

	if req.Name != "" {
		if existing != nil && !strings.EqualFold(req.Name, existing.Name) {

			return nil, ErrDomainCannotRename
		}
		d.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Name), "."))
	}
	if d.Name == "" {
		return nil, ErrInvalidDomain
	}
	if !strings.Contains(d.Name, ".") || strings.ContainsAny(d.Name, " @/\\") {
		return nil, ErrInvalidDomain
	}

	if req.PrimaryHost != "" {
		d.PrimaryHost = strings.TrimSpace(req.PrimaryHost)
	}
	if d.PrimaryHost == "" {
		return nil, ErrInvalidDomain
	}
	if req.PrimaryPort != 0 {
		d.PrimaryPort = req.PrimaryPort
	}
	if d.PrimaryPort < 1 || d.PrimaryPort > 65535 {
		return nil, ErrInvalidDomain
	}
	if req.PrimaryTLS != "" {
		d.PrimaryTLS = req.PrimaryTLS
	}
	if !smtpclient.ValidTLSMode(d.PrimaryTLS) {
		return nil, ErrInvalidDomain
	}
	if req.RetentionHours != 0 {
		d.RetentionHours = req.RetentionHours
	}
	if d.RetentionHours < 1 || d.RetentionHours > 24*30 {
		return nil, ErrInvalidDomain
	}
	if req.MaxQueueMessages != nil {
		d.MaxQueueMessages = req.MaxQueueMessages
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
	}

	if strings.EqualFold(d.PrimaryHost, s.smtp.Hostname) && s.smtp.Hostname != "" {
		return nil, ErrDomainLoop
	}
	return d, ""
}

func (s *Server) domainJSON(ctx context.Context, d *store.Domain) map[string]any {
	out := map[string]any{
		"id": d.ID, "name": d.Name,
		"primary_host": d.PrimaryHost, "primary_port": d.PrimaryPort,
		"primary_tls": d.PrimaryTLS, "retention_hours": d.RetentionHours,
		"max_queue_messages": d.MaxQueueMessages,
		"enabled":            d.Enabled, "created_at": d.CreatedAt,
	}
	if st, err := s.db.PrimaryStatusFor(ctx, d.ID); err == nil {
		out["primary"] = map[string]any{
			"is_up": st.IsUp, "last_check": st.LastCheck,
			"last_up": st.LastUp, "last_down": st.LastDown,
			"last_error": st.LastError,
		}
	}
	if n, err := s.db.CountPendingForDomain(ctx, d.ID); err == nil {
		out["pending"] = n
	}
	return out
}

func (s *Server) handleListQueue(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	allowedIDs, err := s.allowedDomainIDsForUser(r.Context(), u)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	f := store.ListFilter{
		Status:    store.Status(r.URL.Query().Get("status")),
		Direction: store.Direction(r.URL.Query().Get("direction")),
		Limit:     queryInt(r, "limit", 100),
		Offset:    queryInt(r, "offset", 0),
	}
	if id := queryInt(r, "domain_id", 0); id > 0 {
		f.DomainID = int64(id)
	}
	if allowedIDs != nil {
		if f.DomainID > 0 {
			found := false
			for _, aid := range allowedIDs {
				if aid == f.DomainID {
					found = true
					break
				}
			}
			if !found {
				s.ok(w, http.StatusOK, map[string]any{"messages": []any{}, "count": 0})
				return
			}
		} else {
			f.DomainIDs = allowedIDs
		}
	}
	switch r.URL.Query().Get("quarantined") {
	case "true":
		f.Quarantined = 1
	case "false":
		f.Quarantined = -1
	}

	msgs, err := s.db.ListMessages(r.Context(), f)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrQueueListFailed)
		return
	}
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, messageJSON(m))
	}
	s.ok(w, http.StatusOK, map[string]any{"messages": out, "count": len(out)})
}

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.lookupMessage(w, r)
	if !ok {
		return
	}
	s.ok(w, http.StatusOK, messageJSON(m))
}

func (s *Server) handleRawMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.lookupMessage(w, r)
	if !ok {
		return
	}
	u := userFrom(r)

	if err := s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventAdminRead, QueueID: &m.ID, DomainID: &m.DomainID, UserID: &u.ID,
		Data: map[string]any{"ip": clientIP(r), "from": m.EnvelopeFrom, "to": m.EnvelopeTo},
	}); err != nil {
		s.log.Error("refusing raw read: audit entry could not be written", "error", err)
		s.fail(w, r, http.StatusServiceUnavailable, ErrAuditFailed)
		return
	}
	s.log.Warn("admin read a spooled message", "id", m.ID, "admin", u.Email, "ip", clientIP(r))

	body, err := s.blobs.Get(m.ID)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, ErrSpoolReadFailed)
		return
	}
	defer body.Close()

	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", m.ID+".eml"))
	if _, err := io.Copy(w, body); err != nil {
		s.log.Warn("raw message stream interrupted", "id", m.ID, "error", err)
	}
}

func (s *Server) handleRetryMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.lookupMessage(w, r)
	if !ok {
		return
	}
	if err := s.db.RetryNow(r.Context(), m.ID, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusConflict, ErrMessageDelivering)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrRetryFailed)
		return
	}
	u := userFrom(r)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventAdminRetry, QueueID: &m.ID, DomainID: &m.DomainID, UserID: &u.ID,
	})
	s.log.Info("manual retry requested", "id", m.ID, "admin", u.Email)
	s.ok(w, http.StatusOK, map[string]string{"status": "queued for immediate delivery"})
}

func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.lookupMessage(w, r)
	if !ok {
		return
	}

	if m.Status == store.StatusDelivering {
		s.fail(w, r, http.StatusConflict, ErrMessageDelivering)
		return
	}

	u := userFrom(r)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: store.EventAdminDelete, QueueID: &m.ID, DomainID: &m.DomainID, UserID: &u.ID,
		Data: map[string]any{"from": m.EnvelopeFrom, "to": m.EnvelopeTo, "subject": m.Subject},
	})
	if err := s.db.DeleteMessage(r.Context(), m.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrMessageDeleteFailed)
		return
	}
	s.blobs.Delete(m.ID)

	s.log.Warn("admin deleted a queued message", "id", m.ID, "admin", u.Email)
	s.ok(w, http.StatusOK, map[string]string{"deleted": m.ID})
}

func (s *Server) lookupMessage(w http.ResponseWriter, r *http.Request) (*store.Message, bool) {
	id := r.PathValue("id")
	m, err := s.db.GetMessage(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, ErrMessageNotFound)
		return nil, false
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrMessageReadFailed)
		return nil, false
	}
	u := userFrom(r)
	if u != nil {
		can, err := u.CanAccessDomainID(r.Context(), s.db, m.DomainID)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrInternal)
			return nil, false
		}
		if !can {
			s.fail(w, r, http.StatusNotFound, ErrMessageNotFound)
			return nil, false
		}
	}
	return m, true
}

func messageJSON(m *store.Message) map[string]any {
	return map[string]any{
		"id": m.ID, "domain_id": m.DomainID,
		"from": m.EnvelopeFrom, "to": m.EnvelopeTo,
		"subject": m.Subject, "size_bytes": m.SizeBytes,
		"received_at": m.ReceivedAt, "expires_at": m.ExpiresAt,
		"status": m.Status, "attempts": m.Attempts,
		"next_retry_at": m.NextRetryAt, "last_error": m.LastError,
		"delivered_at": m.DeliveredAt, "received_from": m.RemoteAddr,
		"direction": m.Direction, "spam_action": m.SpamAction,
		"spam_score":     m.SpamScore,
		"quarantined_at": m.QuarantinedAt, "quarantine_reason": m.QuarantineReason,
	}
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	allowedIDs, err := s.allowedDomainIDsForUser(r.Context(), u)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	limit := queryInt(r, "limit", 100)
	var events []*store.Event
	if allowedIDs != nil {
		events, err = s.db.ListEventsForDomains(r.Context(), allowedIDs, limit)
	} else {
		events, err = s.db.ListEvents(r.Context(), limit)
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	s.ok(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, unsubscribe := s.hub.subscribe()
	defer unsubscribe()

	fmt.Fprint(w, "retry: 5000\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case raw, open := <-events:
			if !open {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

type smtpUserRequest struct {
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	AllowedDomains []string `json:"allowed_domains"`
	Enabled        *bool    `json:"enabled"`
}

func (s *Server) handleListSMTPUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListSMTPUsers(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrSMTPUserListFailed)
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {

		out = append(out, map[string]any{
			"id": u.ID, "username": u.Username,
			"allowed_domains": u.AllowedDomains, "enabled": u.Enabled,
			"created_at": u.CreatedAt, "last_used_at": u.LastUsedAt,
		})
	}
	s.ok(w, http.StatusOK, map[string]any{"accounts": out})
}

func (s *Server) handleCreateSMTPUser(w http.ResponseWriter, r *http.Request) {
	var req smtpUserRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" || strings.ContainsAny(username, " \t\r\n") {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidUsername)
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidPassword)
		return
	}

	for _, d := range req.AllowedDomains {
		if _, err := s.db.DomainByName(r.Context(), d); err != nil {
			s.fail(w, r, http.StatusBadRequest, ErrDomainNotFound)
			return
		}
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrSMTPUserCreateFailed)
		return
	}
	id, err := s.db.CreateSMTPUser(r.Context(), username, hash, req.AllowedDomains)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			s.fail(w, r, http.StatusConflict, ErrSMTPUserExists)
			return
		}
		s.log.Error("create smtp user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSMTPUserCreateFailed)
		return
	}

	admin := userFrom(r)
	s.log.Info("submission account created", "username", username, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "smtp_user_created", UserID: &admin.ID,
		Data: map[string]any{"username": username, "allowed_domains": req.AllowedDomains},
	})

	s.ok(w, http.StatusCreated, map[string]any{
		"id": id, "username": username,
		"allowed_domains": req.AllowedDomains, "enabled": true,
	})
}

func (s *Server) handleUpdateSMTPUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidAccountID)
		return
	}
	var req smtpUserRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if req.Enabled == nil {
		s.fail(w, r, http.StatusBadRequest, ErrSMTPUserImmutablePassword)
		return
	}
	if err := s.db.SetSMTPUserEnabled(r.Context(), id, *req.Enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrAccountNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrSMTPUserUpdateFailed)
		return
	}
	s.ok(w, http.StatusOK, map[string]any{"id": id, "enabled": *req.Enabled})
}

func (s *Server) handleDeleteSMTPUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidAccountID)
		return
	}
	if err := s.db.DeleteSMTPUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrAccountNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrSMTPUserDeleteFailed)
		return
	}
	admin := userFrom(r)
	s.log.Warn("submission account deleted", "id", id, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "smtp_user_deleted", UserID: &admin.ID, Data: map[string]any{"id": id},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": id})
}
