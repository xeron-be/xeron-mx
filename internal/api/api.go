package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/acme"
	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/clamav"
	"github.com/xeron-be/xeron-mx/internal/cluster"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/diskguard"
	"github.com/xeron-be/xeron-mx/internal/dnsbl"
	"github.com/xeron-be/xeron-mx/internal/filter"
	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/oidc"
	"github.com/xeron-be/xeron-mx/internal/ratelimit"
	"github.com/xeron-be/xeron-mx/internal/spam"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/ui"
	"github.com/xeron-be/xeron-mx/internal/webhook"
)

const sessionCookie = "xeronmx_session"

type Server struct {
	cfg      config.HTTPConfig
	smtp     config.SMTPConfig
	queue    config.QueueConfig
	outbound config.OutboundConfig
	db       *store.DB
	blobs    *blob.Store
	log      *slog.Logger
	hub      *Hub
	limiter  *ratelimit.Limiter
	metrics  *metrics.Collector

	maintenance *maintenance.Manager
	diskPath    string
	minDisk     int64
	diskCheck   diskguard.CheckFunc

	tlsConfig *tls.Config
	certs     CertificateReporter
	filters   *filter.Set
	oidc      *oidc.Provider
	cluster   *cluster.Node
	hooks     *webhook.Dispatcher
	dnsbl     *dnsbl.Checker
	clamav    *clamav.Scanner
	spam      *spam.Checker

	srv *http.Server
}

type CertificateReporter interface {
	CertificateState() acme.State
}

func New(cfg config.HTTPConfig, smtpCfg config.SMTPConfig, queueCfg config.QueueConfig, db *store.DB, blobs *blob.Store, log *slog.Logger, collector *metrics.Collector) *Server {
	s := &Server{
		cfg: cfg, smtp: smtpCfg, queue: queueCfg,
		db: db, blobs: blobs, log: log,
		hub:     NewHub(),
		limiter: ratelimit.New(loginMaxTries, loginWindow),
		metrics: collector,
	}
	if queueCfg.MinFreeDiskBytes > 0 {
		s.minDisk = queueCfg.MinFreeDiskBytes
		s.diskCheck = diskguard.DefaultCheck
	}
	if blobs != nil {
		s.diskPath = blobs.Root()
	}
	s.srv = &http.Server{
		Addr:    cfg.Addr,
		Handler: s.routes(),

		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,

		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return s
}

func (s *Server) SetTLSConfig(cfg *tls.Config)          { s.tlsConfig = cfg }
func (s *Server) SetMaintenance(m *maintenance.Manager) { s.maintenance = m }
func (s *Server) SetDiskGuard(path string, minBytes int64, check diskguard.CheckFunc) {
	s.diskPath = path
	s.minDisk = minBytes
	s.diskCheck = check
}

func (s *Server) SetOutbound(cfg config.OutboundConfig) { s.outbound = cfg }

func (s *Server) SetCertificateReporter(r CertificateReporter) { s.certs = r }

func (s *Server) SetFilters(f *filter.Set) { s.filters = f }

func (s *Server) SetOIDC(p *oidc.Provider) { s.oidc = p }

func (s *Server) SetCluster(n *cluster.Node) { s.cluster = n }

func (s *Server) SetWebhooks(d *webhook.Dispatcher) { s.hooks = d }
func (s *Server) SetDNSBL(d *dnsbl.Checker)         { s.dnsbl = d }
func (s *Server) SetClamAV(c *clamav.Scanner)       { s.clamav = c }
func (s *Server) SetSpam(sp *spam.Checker)          { s.spam = sp }

func (s *Server) Hub() *Hub             { return s.hub }
func (s *Server) Handler() http.Handler { return s.srv.Handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/setup", s.handleSetupStatus)
	mux.HandleFunc("POST /api/v1/setup", s.handleSetup)

	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.authed(s.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", s.authed(s.handleMe))
	mux.HandleFunc("POST /api/v1/auth/password", s.authed(s.handleChangePassword))
	mux.HandleFunc("POST /api/v1/auth/totp/setup", s.authed(s.handleTOTPSetup))
	mux.HandleFunc("POST /api/v1/auth/totp/enable", s.authed(s.handleTOTPEnable))
	mux.HandleFunc("POST /api/v1/auth/totp/disable", s.authed(s.handleTOTPDisable))
	mux.HandleFunc("POST /api/v1/auth/totp/recovery-codes", s.authed(s.handleTOTPRecoveryCodes))

	mux.HandleFunc("GET /api/v1/status", s.authed(s.handleStatus))
	mux.HandleFunc("GET /api/v1/domains", s.authed(s.handleListDomains))
	mux.HandleFunc("GET /api/v1/domains/{id}", s.authed(s.handleGetDomain))
	mux.HandleFunc("GET /api/v1/domains/{id}/dns", s.authed(s.handleDomainDNS))
	mux.HandleFunc("GET /api/v1/domains/{id}/recipients", s.authed(s.handleGetRecipients))
	mux.HandleFunc("PUT /api/v1/domains/{id}/recipients", s.admin(s.handleSetRecipients))
	mux.HandleFunc("GET /api/v1/queue", s.authed(s.handleListQueue))
	mux.HandleFunc("GET /api/v1/queue/{id}", s.authed(s.handleGetMessage))
	mux.HandleFunc("GET /api/v1/events", s.authed(s.handleListEvents))
	mux.HandleFunc("GET /api/v1/smtp-users", s.fleetWide(s.handleListSMTPUsers))
	mux.HandleFunc("GET /api/v1/live", s.authed(s.handleLive))

	mux.HandleFunc("POST /api/v1/domains", s.admin(s.handleCreateDomain))
	mux.HandleFunc("PATCH /api/v1/domains/{id}", s.admin(s.handleUpdateDomain))
	mux.HandleFunc("DELETE /api/v1/domains/{id}", s.admin(s.handleDeleteDomain))
	mux.HandleFunc("POST /api/v1/domains/{id}/test", s.operator(s.handleTestDomain))
	mux.HandleFunc("POST /api/v1/smtp-users", s.admin(s.handleCreateSMTPUser))
	mux.HandleFunc("PATCH /api/v1/smtp-users/{id}", s.admin(s.handleUpdateSMTPUser))
	mux.HandleFunc("DELETE /api/v1/smtp-users/{id}", s.admin(s.handleDeleteSMTPUser))
	mux.HandleFunc("POST /api/v1/queue/{id}/retry", s.operator(s.handleRetryMessage))
	mux.HandleFunc("DELETE /api/v1/queue/{id}", s.operator(s.handleDeleteMessage))

	mux.HandleFunc("GET /api/v1/queue/{id}/raw", s.operator(s.handleRawMessage))

	mux.HandleFunc("GET /api/v1/domains/{id}/dkim", s.authed(s.handleGetDKIM))
	mux.HandleFunc("POST /api/v1/domains/{id}/dkim", s.admin(s.handleCreateDKIM))
	mux.HandleFunc("PATCH /api/v1/domains/{id}/dkim", s.admin(s.handleUpdateDKIM))
	mux.HandleFunc("DELETE /api/v1/domains/{id}/dkim", s.admin(s.handleDeleteDKIM))
	mux.HandleFunc("GET /api/v1/domains/{id}/dkim/check", s.authed(s.handleCheckDKIM))
	mux.HandleFunc("POST /api/v1/domains/{id}/dkim/check", s.authed(s.handleCheckDKIM))

	mux.HandleFunc("GET /api/v1/domains/{id}/dmarc", s.authed(s.handleGetDMARC))
	mux.HandleFunc("POST /api/v1/domains/{id}/dmarc/check", s.authed(s.handleCheckDMARC))

	mux.HandleFunc("GET /api/v1/routes", s.fleetWide(s.handleListRoutes))
	mux.HandleFunc("POST /api/v1/routes", s.admin(s.handleCreateRoute))
	mux.HandleFunc("PATCH /api/v1/routes/{id}", s.admin(s.handleUpdateRoute))
	mux.HandleFunc("DELETE /api/v1/routes/{id}", s.admin(s.handleDeleteRoute))
	mux.HandleFunc("GET /api/v1/routes/test", s.fleetWide(s.handleTestRoute))

	mux.HandleFunc("GET /api/v1/filters", s.fleetWide(s.handleListFilters))
	mux.HandleFunc("POST /api/v1/filters", s.admin(s.handleCreateFilter))
	mux.HandleFunc("PATCH /api/v1/filters/{id}", s.admin(s.handleUpdateFilter))
	mux.HandleFunc("DELETE /api/v1/filters/{id}", s.admin(s.handleDeleteFilter))
	mux.HandleFunc("POST /api/v1/filters/test", s.admin(s.handleTestFilters))
	mux.HandleFunc("POST /api/v1/queue/{id}/release", s.operator(s.handleReleaseMessage))

	mux.HandleFunc("GET /api/v1/security/status", s.authed(s.handleSecurityStatus))
	mux.HandleFunc("POST /api/v1/security/dnsbl/test", s.authed(s.handleTestDNSBL))

	mux.HandleFunc("GET /api/v1/config", s.admin(s.handleExportConfig))
	mux.HandleFunc("POST /api/v1/config", s.admin(s.handleImportConfig))

	mux.HandleFunc("GET /api/v1/tokens", s.admin(s.handleListTokens))
	mux.HandleFunc("POST /api/v1/tokens", s.admin(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.admin(s.handleDeleteToken))

	mux.HandleFunc("GET /api/v1/users", s.admin(s.handleListUsers))
	mux.HandleFunc("POST /api/v1/users", s.admin(s.handleCreateUser))
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.admin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.admin(s.handleDeleteUser))

	mux.HandleFunc("GET /api/v1/webhooks", s.fleetWide(s.handleListWebhooks))
	mux.HandleFunc("GET /api/v1/webhooks/events", s.authed(s.handleWebhookEventTypes))
	mux.HandleFunc("GET /api/v1/webhooks/deliveries", s.fleetWide(s.handleListDeliveries))
	mux.HandleFunc("POST /api/v1/webhooks", s.admin(s.handleCreateWebhook))
	mux.HandleFunc("PATCH /api/v1/webhooks/{id}", s.admin(s.handleUpdateWebhook))
	mux.HandleFunc("DELETE /api/v1/webhooks/{id}", s.admin(s.handleDeleteWebhook))
	mux.HandleFunc("POST /api/v1/webhooks/{id}/test", s.admin(s.handleTestWebhook))

	mux.HandleFunc("GET /api/v1/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /api/v1/auth/oidc/callback", s.handleOIDCCallback)

	mux.HandleFunc("GET /api/v1/cluster", s.fleetWide(s.handleClusterState))
	mux.HandleFunc("DELETE /api/v1/cluster/nodes/{id}", s.admin(s.handleForgetNode))

	mux.HandleFunc("POST "+cluster.HeartbeatPath, s.handleHeartbeat)
	mux.HandleFunc("GET "+cluster.ConfigPath, s.handleClusterConfig)

	mux.HandleFunc("GET /api/v1/maintenance/drain", s.operator(s.handleGetDrain))
	mux.HandleFunc("POST /api/v1/maintenance/drain", s.admin(s.handleSetDrain))

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, r, http.StatusNotFound, ErrNotFound)
	})

	mux.Handle("/", ui.Handler())

	if s.metrics != nil {
		mux.HandleFunc("GET /metrics", s.metrics.Handler())
	}

	return s.withSecurityHeaders(s.withSameOrigin(s.withLogging(mux)))
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", s.cfg.Addr, err)
	}

	useTLS := s.cfg.TLSCert != "" || s.tlsConfig != nil
	s.log.Info("api listener started", "addr", s.cfg.Addr, "tls", useTLS,
		"acme", s.tlsConfig != nil)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.srv.Shutdown(shutdownCtx)
		s.hub.Close()
	}()

	switch {
	case s.tlsConfig != nil:

		s.srv.TLSConfig = s.tlsConfig
		err = s.srv.ServeTLS(ln, "", "")
	case s.cfg.TLSCert != "":
		s.srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = s.srv.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
	default:
		err = s.srv.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("api: serve: %w", err)
	}
	return nil
}

type ctxKey int

const (
	userKey ctxKey = iota
	tokenKey
)

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(userKey).(*store.User)
	return u
}

func tokenFrom(r *http.Request) *store.APIToken {
	t, _ := r.Context().Value(tokenKey).(*store.APIToken)
	return t
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if presented := bearerToken(r); presented != "" {
			s.authedByToken(w, r, presented, next)
			return
		}

		cookie, err := r.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			s.fail(w, r, http.StatusUnauthorized, ErrAuthRequired)
			return
		}
		user, err := s.db.UserBySessionToken(r.Context(), auth.HashToken(cookie.Value))
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.log.Error("session lookup failed", "error", err)
			}

			s.clearSessionCookie(w)
			s.fail(w, r, http.StatusUnauthorized, ErrAuthRequired)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	}
}

func (s *Server) authedByToken(w http.ResponseWriter, r *http.Request, presented string, next http.HandlerFunc) {
	user, tok, err := s.principalForToken(r.Context(), presented)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("api token lookup failed", "error", err)
		}
		s.fail(w, r, http.StatusUnauthorized, ErrInvalidToken)
		return
	}
	s.db.TouchAPIToken(r.Context(), tok.ID)

	ctx := context.WithValue(r.Context(), userKey, user)
	ctx = context.WithValue(ctx, tokenKey, tok)
	next(w, r.WithContext(ctx))
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r); u == nil || u.Role != store.RoleAdmin {
			s.fail(w, r, http.StatusForbidden, ErrAdminRequired)
			return
		}
		next(w, r)
	})
}

func (s *Server) operator(next http.HandlerFunc) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r); u == nil || (u.Role != store.RoleAdmin && u.Role != store.RoleOperator) {
			s.fail(w, r, http.StatusForbidden, ErrAdminRequired)
			return
		}
		next(w, r)
	})
}

func (s *Server) fleetWide(next http.HandlerFunc) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r); u != nil && u.Scoped() {
			s.fail(w, r, http.StatusForbidden, ErrDomainScoped)
			return
		}
		next(w, r)
	})
}

func (s *Server) domainsForUser(ctx context.Context, u *store.User) ([]*store.Domain, error) {
	all, err := s.db.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	if u == nil || !u.Scoped() {
		return all, nil
	}
	allowedMap := make(map[string]bool, len(u.AllowedDomains))
	for _, d := range u.AllowedDomains {
		allowedMap[strings.ToLower(d)] = true
	}
	var filtered []*store.Domain
	for _, d := range all {
		if allowedMap[strings.ToLower(d.Name)] {
			filtered = append(filtered, d)
		}
	}
	return filtered, nil
}

func (s *Server) allowedDomainIDsForUser(ctx context.Context, u *store.User) ([]int64, error) {
	if u == nil || !u.Scoped() {
		return nil, nil
	}
	domains, err := s.domainsForUser(ctx, u)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(domains))
	for i, d := range domains {
		ids[i] = d.ID
	}
	return ids, nil
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")

		h.Set("Cache-Control", "no-store")
		if s.secure() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:

		default:
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
				s.log.Warn("refused a cross-origin request",
					"origin", origin, "method", r.Method, "path", r.URL.Path)
				s.fail(w, r, http.StatusForbidden, ErrCrossOriginRefused)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {

		return false
	}
	return strings.EqualFold(u.Host, host)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		s.log.Debug("http",
			"method", r.Method, "path", r.URL.Path,
			"status", rec.status, "duration", time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) ok(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.log.Warn("response encoding failed", "error", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	if status >= 500 {
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "status", status, "error", code)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",

		HttpOnly: true,

		SameSite: http.SameSiteLaxMode,
		Secure:   s.secure(),
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: s.secure(), MaxAge: -1,
	})
}

func (s *Server) secure() bool { return s.cfg.TLSCert != "" || s.tlsConfig != nil }

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

const (
	loginWindow   = 15 * time.Minute
	loginMaxTries = 10
)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isEmail(s string) bool {
	at := strings.LastIndex(s, "@")
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n")
}
