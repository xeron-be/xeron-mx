package submission

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/diskguard"
	"github.com/xeron-be/xeron-mx/internal/mailutil"
	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/netlimit"
	"github.com/xeron-be/xeron-mx/internal/ratelimit"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	authWindow   = 15 * time.Minute
	authMaxTries = 8
)

type Notifier interface {
	Notify(event string, payload map[string]any)
}

type Server struct {
	cfg    config.OutboundConfig
	queue  config.QueueConfig
	db     *store.DB
	blobs  *blob.Store
	log    *slog.Logger
	notify Notifier
	count  *metrics.Counters

	maintenance *maintenance.Manager
	diskPath    string
	minDisk     int64
	diskCheck   diskguard.CheckFunc

	limiter *ratelimit.Limiter

	srv *smtp.Server
}

func New(cfg config.OutboundConfig, queue config.QueueConfig, db *store.DB, blobs *blob.Store, log *slog.Logger, notify Notifier, count *metrics.Counters) *Server {
	s := &Server{cfg: cfg, queue: queue, db: db, blobs: blobs, log: log,
		notify: notify, count: count, limiter: ratelimit.New(authMaxTries, authWindow)}
	if queue.MinFreeDiskBytes > 0 {
		s.minDisk = queue.MinFreeDiskBytes
		s.diskCheck = diskguard.DefaultCheck
	}
	if blobs != nil {
		s.diskPath = blobs.Root()
	}

	srv := smtp.NewServer(smtp.BackendFunc(s.newSession))
	srv.Addr = cfg.Addr
	srv.MaxMessageBytes = cfg.MaxMessageBytes
	srv.MaxRecipients = 200
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = 5 * time.Minute

	srv.AllowInsecureAuth = !cfg.RequireTLS
	srv.EnableSMTPUTF8 = true
	srv.ErrorLog = logger{log}

	s.srv = srv
	return s
}

func (s *Server) SetTLSConfig(cfg *tls.Config)          { s.srv.TLSConfig = cfg }
func (s *Server) SetMaintenance(m *maintenance.Manager) { s.maintenance = m }
func (s *Server) SetDiskGuard(path string, minBytes int64, check diskguard.CheckFunc) {
	s.diskPath = path
	s.minDisk = minBytes
	s.diskCheck = check
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.RequireTLS && s.srv.TLSConfig == nil {
		return fmt.Errorf("submission: outbound.require_tls is on but no certificate is configured: " +
			"set http.acme or smtp.tls_cert, or set outbound.require_tls: false to accept the risk")
	}

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("submission: listen on %s: %w", s.cfg.Addr, err)
	}
	ln = netlimit.Listen(ln, s.cfg.MaxConnections,
		"421 4.7.0 Too many concurrent connections, try again later\r\n")

	s.log.Info("submission listener started",
		"addr", s.cfg.Addr, "mode", s.cfg.Mode,
		"relay", s.cfg.RelayHost, "require_tls", s.cfg.RequireTLS,
		"max_connections", s.cfg.MaxConnections)

	go func() {
		<-ctx.Done()
		s.srv.Close()
	}()

	if err := s.srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
		return fmt.Errorf("submission: serve: %w", err)
	}
	return nil
}

func (s *Server) Shutdown() error { return s.srv.Close() }

func (s *Server) newSession(c *smtp.Conn) (smtp.Session, error) {
	remote := ""
	if addr := c.Conn().RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	s.count.SMTPConnections.Add(1)
	if s.maintenance != nil && s.maintenance.IsDraining() {
		return nil, &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      "Service temporarily unavailable, server is draining for maintenance",
		}
	}
	return &session{srv: s, remote: remote, log: s.log.With("remote", remote)}, nil
}

type session struct {
	srv    *Server
	remote string
	log    *slog.Logger

	user     *store.SMTPUser
	from     string
	rcpts    []string
	domainID int64
}

func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
	s.domainID = 0
}

func (s *session) Logout() error { return nil }

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnsupported
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		ip := hostOnly(s.remote)
		if !s.srv.limiter.Allow(ip) {
			s.log.Warn("submission auth throttled", "username", username, "ip", ip)
			return &smtp.SMTPError{
				Code:         454,
				EnhancedCode: smtp.EnhancedCode{4, 7, 0},
				Message:      "Too many authentication attempts, try again later",
			}
		}

		if identity != "" && identity != username {
			s.log.Warn("submission auth refused", "username", username,
				"reason", "authorization identity is not supported")
			return smtp.ErrAuthFailed
		}
		if len(password) > auth.MaxPasswordBytes {
			s.log.Warn("submission auth failed", "username", username, "reason", "password too long")
			return smtp.ErrAuthFailed
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		user, err := s.srv.db.SMTPUserByName(ctx, username)
		if err != nil {

			auth.HashPassword(password)
			s.log.Warn("submission auth failed", "username", username, "reason", "unknown account")
			return smtp.ErrAuthFailed
		}
		ok, err := auth.VerifyPassword(password, user.PasswordHash)
		if err != nil || !ok {
			s.log.Warn("submission auth failed", "username", username, "reason", "bad password")
			return smtp.ErrAuthFailed
		}
		if !user.Enabled {
			s.log.Warn("submission auth refused", "username", username, "reason", "account disabled")
			return smtp.ErrAuthFailed
		}

		s.srv.limiter.Reset(ip)

		s.user = user
		s.srv.db.TouchSMTPUser(ctx, user.ID)
		s.log.Info("submission authenticated", "username", username)
		return nil
	}), nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.user == nil {
		return smtp.ErrAuthRequired
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !s.user.MaySend(from) {
		s.log.Warn("submission refused: sender not allowed for this account",
			"username", s.user.Username, "from", from)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "You are not allowed to send as that address",
		}
	}

	domainName := domainOf(from)
	if domainName == "" {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "A null return path cannot be used for submission",
		}
	}
	d, err := s.srv.db.DomainByName(ctx, domainName)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !d.Enabled) {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "That sender domain is not configured here",
		}
	}
	if err != nil {
		s.log.Error("submission: domain lookup failed", "error", err)
		return tempError("temporarily unable to accept submissions")
	}

	stats, err := s.srv.db.Stats(ctx)
	if err != nil {
		return tempError("temporarily unable to accept submissions")
	}

	if s.srv.maintenance != nil && s.srv.maintenance.IsDraining() {
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      "Service temporarily unavailable, server is draining for maintenance",
		}
	}

	if s.srv.minDisk > 0 && s.srv.diskCheck != nil && s.srv.diskPath != "" {
		avail, err := s.srv.diskCheck(s.srv.diskPath)
		if err == nil && avail < uint64(s.srv.minDisk) {
			return &smtp.SMTPError{
				Code:         452,
				EnhancedCode: smtp.EnhancedCode{4, 3, 1},
				Message:      "Insufficient system storage, try again later",
			}
		}
	}

	q := s.srv.queue
	if q.MaxMessages > 0 && stats.Pending >= q.MaxMessages {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 3, 1},
			Message:      "Insufficient storage, try again later",
		}
	}

	s.from = from
	s.domainID = d.ID
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.user == nil {
		return smtp.ErrAuthRequired
	}
	if s.domainID == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Send MAIL FROM first",
		}
	}
	if domainOf(to) == "" {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Malformed recipient address",
		}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if s.user == nil {
		return smtp.ErrAuthRequired
	}
	if s.domainID == 0 || len(s.rcpts) == 0 {
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	id, err := mailutil.NewID()
	if err != nil {
		return tempError("temporarily unable to accept the message")
	}

	head, rest := mailutil.PeekHeaders(r, 64<<10)
	subject := mailutil.ExtractSubject(head)

	written, err := s.srv.blobs.Put(id, rest, s.srv.cfg.MaxMessageBytes)
	if err != nil {
		s.srv.blobs.Delete(id)
		if strings.Contains(err.Error(), "exceeds") {
			return &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 3, 4},
				Message:      "Message exceeds maximum size",
			}
		}
		s.log.Error("submission spool write failed", "id", id, "error", err)
		return tempError("temporarily unable to store the message")
	}

	now := time.Now().UTC()
	msg := &store.Message{
		ID:           id,
		DomainID:     s.domainID,
		EnvelopeFrom: s.from,
		EnvelopeTo:   s.rcpts,
		Subject:      subject,
		SizeBytes:    written,
		ReceivedAt:   now,
		ExpiresAt:    now.Add(s.srv.queue.Retention),
		NextRetryAt:  now,
		RemoteAddr:   s.remote,
		Direction:    store.DirectionOutbound,
	}
	if err := s.srv.db.Enqueue(ctx, msg); err != nil {
		s.srv.blobs.Delete(id)
		s.log.Error("submission enqueue failed", "id", id, "error", err)
		return tempError("temporarily unable to store the message")
	}

	s.srv.count.MessagesReceived.Add(1)
	s.srv.count.BytesReceived.Add(written)
	s.log.Info("submission accepted",
		"id", id, "from", s.from, "recipients", len(s.rcpts), "bytes", written)

	domainID := s.domainID
	if err := s.srv.db.RecordEvent(ctx, &store.Event{
		Type: store.EventMailReceived, QueueID: &id, DomainID: &domainID,
		Data: map[string]any{
			"direction": "outbound", "from": s.from, "to": s.rcpts,
			"bytes": written, "submitted_by": s.user.Username,
		},
	}); err != nil {
		s.log.Warn("submission event not recorded", "error", err)
	}
	if s.srv.notify != nil {
		s.srv.notify.Notify(store.EventMailReceived, map[string]any{
			"id": id, "direction": "outbound", "subject": subject,
		})
	}
	return nil
}

func tempError(msg string) *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message:      msg,
	}
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

type logger struct{ log *slog.Logger }

func (l logger) Printf(format string, v ...any) {
	l.log.Warn("submission: " + fmt.Sprintf(format, v...))
}
func (l logger) Println(v ...any) {
	l.log.Warn("submission: " + fmt.Sprintln(v...))
}
