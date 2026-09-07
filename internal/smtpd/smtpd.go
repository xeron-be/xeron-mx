package smtpd

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

	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/clamav"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/diskguard"
	"github.com/xeron-be/xeron-mx/internal/dnsbl"
	"github.com/xeron-be/xeron-mx/internal/filter"
	"github.com/xeron-be/xeron-mx/internal/mailutil"
	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/netlimit"
	"github.com/xeron-be/xeron-mx/internal/spam"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type Notifier interface {
	Notify(event string, payload map[string]any)
}

type Server struct {
	cfg     config.SMTPConfig
	queue   config.QueueConfig
	db      *store.DB
	blobs   *blob.Store
	log     *slog.Logger
	notify  Notifier
	count   *metrics.Counters
	spam    *spam.Checker
	filters *filter.Set
	dnsbl   *dnsbl.Checker
	clamav  *clamav.Scanner

	maintenance *maintenance.Manager
	diskPath    string
	minDisk     int64
	diskCheck   diskguard.CheckFunc

	spamDefer bool

	srv *smtp.Server
}

func New(cfg config.SMTPConfig, queue config.QueueConfig, db *store.DB, blobs *blob.Store, log *slog.Logger, notify Notifier, count *metrics.Counters, checker *spam.Checker, filters *filter.Set) (*Server, error) {
	s := &Server{cfg: cfg, queue: queue, db: db, blobs: blobs, log: log,
		notify: notify, count: count, spam: checker, filters: filters}
	if checker != nil {
		s.spamDefer = checker.DeferAllowed()
	}
	if queue.MinFreeDiskBytes > 0 {
		s.minDisk = queue.MinFreeDiskBytes
		s.diskCheck = diskguard.DefaultCheck
	}
	if blobs != nil {
		s.diskPath = blobs.Root()
	}

	srv := smtp.NewServer(smtp.BackendFunc(s.newSession))
	srv.Addr = cfg.Addr
	srv.Domain = cfg.Hostname
	srv.ReadTimeout = cfg.ReadTimeout
	srv.WriteTimeout = cfg.WriteTimeout
	srv.MaxMessageBytes = cfg.MaxMessageBytes
	srv.MaxRecipients = cfg.MaxRecipients
	srv.AllowInsecureAuth = false
	srv.EnableSMTPUTF8 = true
	srv.ErrorLog = smtpLogger{log}

	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("smtpd: load TLS keypair: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	s.srv = srv
	return s, nil
}

func (s *Server) SetTLSConfig(cfg *tls.Config)          { s.srv.TLSConfig = cfg }
func (s *Server) SetDNSBL(c *dnsbl.Checker)             { s.dnsbl = c }
func (s *Server) SetClamAV(c *clamav.Scanner)           { s.clamav = c }
func (s *Server) SetMaintenance(m *maintenance.Manager) { s.maintenance = m }
func (s *Server) SetDiskGuard(path string, minBytes int64, check diskguard.CheckFunc) {
	s.diskPath = path
	s.minDisk = minBytes
	s.diskCheck = check
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("smtpd: listen on %s: %w", s.cfg.Addr, err)
	}

	ln = netlimit.Listen(ln, s.cfg.MaxConnections,
		"421 4.7.0 Too many concurrent connections, try again later\r\n")

	s.log.Info("smtp listener started",
		"addr", s.cfg.Addr,
		"hostname", s.cfg.Hostname,
		"starttls", s.srv.TLSConfig != nil,
		"max_connections", s.cfg.MaxConnections,
		"max_message_bytes", s.cfg.MaxMessageBytes)

	go func() {
		<-ctx.Done()
		s.srv.Close()
	}()

	if err := s.srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
		return fmt.Errorf("smtpd: serve: %w", err)
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
		s.count.MessagesRejected.Add(1)
		s.log.Info("smtp connection refused: server is draining for maintenance", "remote", remote)
		return nil, &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      "Service temporarily unavailable, server is draining for maintenance",
		}
	}

	if s.dnsbl != nil && s.dnsbl.Enabled() {
		res, err := s.dnsbl.Check(context.Background(), remote)
		if err == nil && res != nil && res.Listed {
			s.count.MessagesRejected.Add(1)
			s.log.Warn("client blocked by dnsbl", "remote", remote, "zone", res.Zone, "record", res.Record)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.db.RecordEvent(ctx, &store.Event{
				Type: store.EventMailRejected,
				Data: map[string]any{
					"reason": "dnsbl", "remote": remote, "zone": res.Zone, "record": res.Record,
				},
			})
			cancel()
			return nil, &smtp.SMTPError{
				Code:         554,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      fmt.Sprintf("Client host [%s] blocked using %s", remote, res.Zone),
			}
		}
	}

	return &session{
		srv:    s,
		conn:   c,
		remote: remote,
		log:    s.log.With("remote", remote),
	}, nil
}

type session struct {
	srv    *Server
	conn   *smtp.Conn
	remote string
	log    *slog.Logger

	from     string
	rcpts    []string
	domainID int64
	domain   string
}

func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
	s.domainID = 0
	s.domain = ""
}

func (s *session) Logout() error { return nil }

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.srv.maintenance != nil && s.srv.maintenance.IsDraining() {
		s.srv.count.MessagesRejected.Add(1)
		s.log.Info("mail refused: server is draining for maintenance", "remote", s.remote)
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 3, 2},
			Message:      "Service temporarily unavailable, server is draining for maintenance",
		}
	}

	if s.srv.minDisk > 0 && s.srv.diskCheck != nil && s.srv.diskPath != "" {
		avail, err := s.srv.diskCheck(s.srv.diskPath)
		if err == nil && avail < uint64(s.srv.minDisk) {
			s.srv.count.MessagesRejected.Add(1)
			s.log.Warn("insufficient disk space for spool, refusing with 452",
				"available_bytes", avail, "min_required", s.srv.minDisk)
			s.recordEvent(ctx, store.EventQueueFull, nil, map[string]any{
				"reason": "disk_space", "available_bytes": avail, "min_required": s.srv.minDisk,
			})
			if s.srv.notify != nil {
				s.srv.notify.Notify(store.EventQueueFull, map[string]any{
					"reason": "disk_space", "available_bytes": avail, "min_required": s.srv.minDisk,
				})
			}
			return &smtp.SMTPError{
				Code:         452,
				EnhancedCode: smtp.EnhancedCode{4, 3, 1},
				Message:      "Insufficient system storage, try again later",
			}
		}
	}

	stats, err := s.srv.db.Stats(ctx)
	if err != nil {
		s.log.Error("queue stats failed", "error", err)
		return tempError("temporarily unable to accept mail")
	}
	q := s.srv.queue
	if (q.MaxMessages > 0 && stats.Pending >= q.MaxMessages) ||
		(q.MaxBytes > 0 && stats.PendingBytes >= q.MaxBytes) {
		s.srv.count.MessagesRejected.Add(1)
		s.log.Warn("spool full, refusing with 452",
			"pending", stats.Pending, "pending_bytes", stats.PendingBytes)
		s.recordEvent(ctx, store.EventQueueFull, nil, map[string]any{
			"pending": stats.Pending, "pending_bytes": stats.PendingBytes,
		})
		if s.srv.notify != nil {
			s.srv.notify.Notify(store.EventQueueFull, map[string]any{
				"pending": stats.Pending, "pending_bytes": stats.PendingBytes,
			})
		}
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 3, 1},
			Message:      "Insufficient storage, try again later",
		}
	}

	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	at := strings.LastIndex(to, "@")
	if at < 0 || at == len(to)-1 {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Malformed recipient address",
		}
	}
	domainName := strings.ToLower(to[at+1:])

	d, err := s.srv.db.DomainByName(ctx, domainName)
	if errors.Is(err, store.ErrNotFound) {
		s.srv.count.MessagesRejected.Add(1)
		s.log.Info("rejected recipient for unconfigured domain", "domain", domainName)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Relay access denied",
		}
	}
	if err != nil {
		s.log.Error("domain lookup failed", "domain", domainName, "error", err)
		return tempError("temporarily unable to verify recipient")
	}
	if !d.Enabled {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Relay access denied",
		}
	}

	if s.domainID != 0 && s.domainID != d.ID {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      "Too many recipient domains in one transaction",
		}
	}

	if d.MaxQueueMessages != nil && *d.MaxQueueMessages > 0 {
		pending, err := s.srv.db.CountPendingForDomain(ctx, d.ID)
		if err != nil {
			s.log.Error("per-domain count failed", "domain", domainName, "error", err)
			return tempError("temporarily unable to accept mail")
		}
		if pending >= *d.MaxQueueMessages {
			return &smtp.SMTPError{
				Code:         452,
				EnhancedCode: smtp.EnhancedCode{4, 3, 1},
				Message:      "Recipient domain queue is full, try again later",
			}
		}
	}

	s.domainID = d.ID
	s.domain = d.Name
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if s.domainID == 0 || len(s.rcpts) == 0 {
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}

	id, err := newID()
	if err != nil {
		s.log.Error("id generation failed", "error", err)
		return tempError("temporarily unable to accept mail")
	}

	peeked, rest := peekHeaders(r, 64<<10)
	subject := extractSubject(peeked)

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
		s.log.Error("spool write failed", "id", id, "error", err)
		return tempError("temporarily unable to store message")
	}

	var quarantine string
	if s.srv.filters != nil {
		fv := s.srv.filters.Evaluate(filter.Message{
			From: s.from, To: s.rcpts, Subject: subject,
		})
		switch {
		case fv.Reject():
			s.srv.blobs.Delete(id)
			s.srv.count.MessagesRejected.Add(1)
			s.srv.db.RecordFilterMatch(ctx, fv.FilterID)
			s.log.Info("rejected by filter", "filter", fv.Name, "field", fv.Field)
			s.recordEvent(ctx, store.EventMailRejected, nil, map[string]any{
				"reason": "filter", "filter": fv.Name, "field": fv.Field,
				"from": s.from, "to": s.rcpts,
			})
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "Message rejected by policy",
			}
		case fv.Quarantine():
			quarantine = fv.Reason()
			s.srv.db.RecordFilterMatch(ctx, fv.FilterID)
			s.log.Info("quarantined by filter", "id", id, "filter", fv.Name, "field", fv.Field)
		}
	}

	verdict := s.checkSpam(ctx, id, written)
	switch {
	case verdict.Reject():
		s.srv.blobs.Delete(id)
		s.srv.count.MessagesRejected.Add(1)
		s.log.Info("rejected as spam", "id", id, "score", verdict.Score, "symbols", verdict.Symbols)
		s.recordEvent(ctx, store.EventMailRejected, nil, map[string]any{
			"reason": "spam", "score": verdict.Score, "from": s.from, "to": s.rcpts,
		})
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Message rejected as spam",
		}
	case verdict.Defer() && s.srv.cfgSpamDefer():

		s.srv.blobs.Delete(id)
		s.log.Info("deferred by the spam filter", "id", id, "action", verdict.Action)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 7, 1},
			Message:      "Try again later",
		}
	}

	malware, err := s.checkMalware(ctx, id)
	if err != nil {
		s.log.Warn("malware scan failed, failing open", "id", id, "error", err)
	} else if malware != nil && malware.Infected {
		s.log.Warn("malware detected", "id", id, "virus", malware.VirusName, "action", s.srv.clamav.Action())
		if s.srv.clamav.Action() == "reject" {
			s.srv.blobs.Delete(id)
			s.srv.count.MessagesRejected.Add(1)
			s.recordEvent(ctx, store.EventMailRejected, nil, map[string]any{
				"reason": "malware", "virus": malware.VirusName, "from": s.from, "to": s.rcpts,
			})
			return &smtp.SMTPError{
				Code:         554,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      fmt.Sprintf("Malware detected: %s", malware.VirusName),
			}
		}
		quarantine = fmt.Sprintf("malware: %s", malware.VirusName)
	}

	now := time.Now().UTC()
	retention := s.srv.queue.Retention
	if d, err := s.srv.db.DomainByID(ctx, s.domainID); err == nil && d.RetentionHours > 0 {
		retention = time.Duration(d.RetentionHours) * time.Hour
	}

	msg := &store.Message{
		ID:           id,
		DomainID:     s.domainID,
		EnvelopeFrom: s.from,
		EnvelopeTo:   s.rcpts,
		Subject:      subject,
		SizeBytes:    written,
		ReceivedAt:   now,
		ExpiresAt:    now.Add(retention),

		NextRetryAt: now,
		RemoteAddr:  s.remote,
		Direction:   store.DirectionInbound,
		SpamAction:  string(verdict.Action),
	}
	if !verdict.Skipped {
		score := verdict.Score
		msg.SpamScore = &score
	}
	if err := s.srv.db.Enqueue(ctx, msg); err != nil {
		s.srv.blobs.Delete(id)
		s.log.Error("enqueue failed", "id", id, "error", err)
		return tempError("temporarily unable to store message")
	}
	if quarantine != "" {
		if err := s.srv.db.Quarantine(ctx, id, quarantine); err != nil {
			s.log.Error("accepted but could not quarantine", "id", id, "error", err)
		} else {
			s.recordEvent(ctx, store.EventMailQuarantined, &id, map[string]any{
				"reason": quarantine, "from": s.from, "to": s.rcpts,
			})
			if s.srv.notify != nil {
				s.srv.notify.Notify(store.EventMailQuarantined, map[string]any{
					"id": id, "reason": quarantine, "subject": subject,
				})
			}
		}
	}

	s.srv.count.MessagesReceived.Add(1)
	s.srv.count.BytesReceived.Add(written)
	s.log.Info("message accepted",
		"id", id, "domain", s.domain, "from", s.from,
		"recipients", len(s.rcpts), "bytes", written)

	s.recordEvent(ctx, store.EventMailReceived, &id, map[string]any{
		"from": s.from, "to": s.rcpts, "bytes": written, "domain": s.domain,
	})
	if s.srv.notify != nil {
		s.srv.notify.Notify(store.EventMailReceived, map[string]any{
			"id": id, "domain": s.domain, "subject": subject, "bytes": written,
		})
	}
	return nil
}

func (s *session) checkSpam(ctx context.Context, id string, plaintextSize int64) spam.Verdict {
	if s.srv.spam == nil || !s.srv.spam.Enabled() {
		return spam.Verdict{Action: spam.ActionNone, Skipped: true}
	}
	body, err := s.srv.blobs.Get(id)
	if err != nil {
		s.log.Warn("could not read the spooled body for scanning", "id", id, "error", err)
		return spam.Verdict{Action: spam.ActionNone, Skipped: true}
	}
	defer body.Close()

	helo := ""
	if s.conn != nil {
		helo = s.conn.Hostname()
	}
	return s.srv.spam.Check(ctx, spam.Envelope{
		From:       s.from,
		To:         s.rcpts,
		HeloName:   helo,
		RemoteAddr: s.remote,
		QueueID:    id,
	}, body, plaintextSize)
}

func (s *session) checkMalware(ctx context.Context, id string) (*clamav.Result, error) {
	if s.srv.clamav == nil || !s.srv.clamav.Enabled() {
		return &clamav.Result{Infected: false}, nil
	}
	body, err := s.srv.blobs.Get(id)
	if err != nil {
		s.log.Warn("could not read spooled body for malware scan", "id", id, "error", err)
		return &clamav.Result{Infected: false}, nil
	}
	defer body.Close()
	return s.srv.clamav.Scan(ctx, body)
}

func (s *Server) cfgSpamDefer() bool { return s.spamDefer }

func (s *session) recordEvent(ctx context.Context, typ string, queueID *string, data map[string]any) {
	e := &store.Event{Type: typ, QueueID: queueID, Data: data}
	if s.domainID != 0 {
		id := s.domainID
		e.DomainID = &id
	}
	if err := s.srv.db.RecordEvent(ctx, e); err != nil {

		s.log.Warn("event not recorded", "type", typ, "error", err)
	}
}

func tempError(msg string) *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message:      msg,
	}
}

func newID() (string, error) { return mailutil.NewID() }
func peekHeaders(r io.Reader, limit int) ([]byte, io.Reader) {
	return mailutil.PeekHeaders(r, limit)
}
func extractSubject(head []byte) string { return mailutil.ExtractSubject(head) }

type smtpLogger struct{ log *slog.Logger }

func (l smtpLogger) Printf(format string, v ...interface{}) {
	l.log.Warn("smtp: " + fmt.Sprintf(format, v...))
}

func (l smtpLogger) Println(v ...interface{}) {
	l.log.Warn("smtp: " + fmt.Sprintln(v...))
}
