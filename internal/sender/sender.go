package sender

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/arc"
	"github.com/xeron-be/xeron-mx/internal/authres"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/dkim"
	"github.com/xeron-be/xeron-mx/internal/dsn"
	"github.com/xeron-be/xeron-mx/internal/mailutil"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type Notifier interface {
	Notify(event string, payload map[string]any)
}

type Sender struct {
	cfg    config.QueueConfig
	db     *store.DB
	blobs  *blob.Store
	log    *slog.Logger
	notify Notifier
	wake   <-chan int64
	count  *metrics.Counters

	outbound config.OutboundConfig

	hostname string

	resolver   mxLookup
	directAddr func(host string) (string, int)
}

func New(cfg config.QueueConfig, db *store.DB, blobs *blob.Store, log *slog.Logger, notify Notifier, wake <-chan int64, count *metrics.Counters, outbound config.OutboundConfig, hostname string) *Sender {
	return &Sender{
		cfg: cfg, db: db, blobs: blobs, log: log, notify: notify,
		wake: wake, count: count, outbound: outbound, hostname: hostname,
	}
}

func (s *Sender) Run(ctx context.Context) {
	s.log.Info("delivery workers started",
		"workers", s.cfg.Workers,
		"retry_base", s.cfg.RetryBase,
		"retry_max", s.cfg.RetryMax)

	if n, err := s.db.ReleaseOrphanedClaims(ctx, time.Now().UTC()); err != nil {
		s.log.Error("could not release orphaned claims", "error", err)
	} else if n > 0 {
		s.log.Warn("requeued messages left claimed by a previous run", "count", n)
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	maintenance := time.NewTicker(5 * time.Minute)
	defer maintenance.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("delivery workers stopped")
			return
		case <-ticker.C:
			s.pass(ctx)
		case <-s.wake:

			s.pass(ctx)
		case <-maintenance.C:
			s.maintain(ctx)
		}
	}
}

func (s *Sender) pass(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		batch, err := s.db.ClaimBatch(ctx, workerID(), s.cfg.Workers*4, time.Now().UTC())
		if err != nil {
			s.log.Error("claim batch failed", "error", err)
			return
		}
		claim := s.db.ClaimOutboundBatch
		if !s.outbound.Enabled {
			claim = s.db.ClaimBounceBatch
		}
		if s.outbound.Enabled || s.cfg.Bounces == config.BouncesAuthenticated {
			out, err := claim(ctx, workerID(), s.cfg.Workers*4, time.Now().UTC())
			if err != nil {
				s.log.Error("claim outbound batch failed", "error", err)
			} else {
				batch = append(batch, out...)
			}
		}
		if len(batch) == 0 {
			return
		}

		jobs := make(chan *store.Message)
		var wg sync.WaitGroup
		for i := 0; i < s.cfg.Workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for m := range jobs {
					s.deliver(ctx, m)
				}
			}()
		}
		for _, m := range batch {
			select {
			case jobs <- m:
			case <-ctx.Done():
			}
		}
		close(jobs)
		wg.Wait()
	}
}

func (s *Sender) deliver(ctx context.Context, m *store.Message) {
	log := s.log.With("id", m.ID, "attempt", m.Attempts+1)

	d, err := s.db.DomainByID(ctx, m.DomainID)
	if err != nil {
		log.Error("domain lookup failed", "error", err)
		s.defer_(ctx, m, "domain lookup failed: "+err.Error())
		return
	}

	body, err := s.blobs.Get(m.ID)
	if err != nil {

		log.Error("message body unreadable, giving up", "error", err)
		if err := s.db.MarkFailed(ctx, m.ID, "message body unreadable: "+err.Error()); err != nil {
			log.Error("could not mark failed", "error", err)
		}
		s.bounce(ctx, m, eachRecipient(m.EnvelopeTo, dsn.Lost))
		s.record(ctx, store.EventMailFailed, m, map[string]any{"reason": "body unreadable"})
		return
	}
	closeBody := sync.OnceFunc(func() { body.Close() })
	defer closeBody()

	attemptCtx, cancel := context.WithTimeout(ctx, s.cfg.DeliveryTimeout)
	defer cancel()

	var res recipients
	if m.Direction == store.DirectionOutbound {
		res, err = s.sendOutbound(attemptCtx, m, body)
	} else {
		payload := s.sealARC(attemptCtx, d, m, body)
		res, err = send(attemptCtx, d, m, payload, s.spamHeaders(m), s.destinationPolicy())
	}
	if err == nil {
		s.settle(ctx, log, m, d, res, closeBody)
		return
	}

	var permanent *smtp.SMTPError
	if errors.As(err, &permanent) && permanent.Code >= 500 && permanent.Code < 600 {
		s.count.MessagesFailed.Add(1)
		log.Warn("permanently rejected by "+peer(m), "code", permanent.Code, "error", err)
		if err := s.db.MarkFailed(ctx, m.ID, err.Error()); err != nil {
			log.Error("could not mark failed", "error", err)
		}
		s.bounce(ctx, m, eachRecipient(m.EnvelopeTo, func(rcpt string) dsn.Failure { return dsn.FromError(rcpt, err) }))
		closeBody()
		s.blobs.Delete(m.ID)
		s.record(ctx, store.EventMailFailed, m, map[string]any{
			"domain": d.Name, "code": permanent.Code, "error": err.Error(),
		})
		return
	}

	s.count.MessagesDeferred.Add(1)
	log.Info("deferred", "error", err)
	s.defer_(ctx, m, err.Error())
}

func (s *Sender) settle(ctx context.Context, log *slog.Logger, m *store.Message, d *store.Domain, res recipients, closeBody func()) {
	if len(res.rejected) > 0 {
		rejected := addresses(res.rejected)
		log.Warn("recipients permanently rejected by "+peer(m), "recipients", rejected, "error", res.rejected[0].err)
		s.record(ctx, store.EventMailFailed, m, map[string]any{
			"domain": d.Name, "to": rejected, "error": res.rejected[0].err.Error(),
		})
		failures := make([]dsn.Failure, len(res.rejected))
		for i, f := range res.rejected {
			failures[i] = dsn.FromError(f.rcpt, f.err)
		}
		s.bounce(ctx, m, failures)
	}

	if len(res.deferred) > 0 {
		if len(res.accepted) > 0 {
			log.Info("delivered to some recipients", "domain", d.Name, "recipients", len(res.accepted),
				"remaining", len(res.deferred))
			s.record(ctx, store.EventMailDelivered, m, map[string]any{"domain": d.Name, "to": res.accepted})
		}
		if err := s.db.SetRecipients(ctx, m.ID, addresses(res.deferred)); err != nil {
			log.Error("could not narrow the recipients still to deliver", "error", err)
		}
		s.count.MessagesDeferred.Add(1)
		log.Info("deferred", "error", res.deferred[0].err)
		s.defer_(ctx, m, res.deferred[0].err.Error())
		return
	}

	if len(res.accepted) == 0 {
		reason := "no recipients left to deliver to"
		if len(res.rejected) > 0 {
			reason = res.rejected[0].err.Error()
		}
		s.count.MessagesFailed.Add(1)
		if err := s.db.MarkFailed(ctx, m.ID, reason); err != nil {
			log.Error("could not mark failed", "error", err)
		}
		closeBody()
		s.blobs.Delete(m.ID)
		return
	}

	if err := s.db.MarkDelivered(ctx, m.ID, time.Now().UTC()); err != nil {
		log.Error("delivered but could not record it", "error", err)
		return
	}
	closeBody()
	if err := s.blobs.Delete(m.ID); err != nil {
		log.Warn("delivered but body not removed", "error", err)
	}
	s.count.MessagesDelivered.Add(1)
	log.Info("delivered", "domain", d.Name, "direction", m.Direction, "recipients", len(res.accepted))
	s.record(ctx, store.EventMailDelivered, m, map[string]any{"domain": d.Name})
}

func eachRecipient(rcpts []string, f func(string) dsn.Failure) []dsn.Failure {
	out := make([]dsn.Failure, len(rcpts))
	for i, r := range rcpts {
		out[i] = f(r)
	}
	return out
}

func (s *Sender) shouldBounce(m *store.Message) bool {
	return s.cfg.Bounces == config.BouncesAuthenticated && m.EnvelopeFrom != "" &&
		(m.Direction == store.DirectionOutbound || m.SenderAuthenticated)
}

func (s *Sender) bounce(ctx context.Context, m *store.Message, failures []dsn.Failure) {
	if len(failures) == 0 || !s.shouldBounce(m) {
		return
	}
	log := s.log.With("id", m.ID, "to", m.EnvelopeFrom)

	var headers []byte
	if r, err := s.blobs.Get(m.ID); err == nil {
		headers = dsn.HeadersOf(r)
		r.Close()
	}
	now := time.Now().UTC()
	raw, err := dsn.Build(dsn.Report{
		ReportingMTA: s.heloName(), QueueID: m.ID, Arrival: m.ReceivedAt,
		Recipient: m.EnvelopeFrom, Failures: failures, Headers: headers,
	}, now)
	if err != nil {
		log.Error("could not build a bounce", "error", err)
		return
	}

	id, err := mailutil.NewID()
	if err != nil {
		log.Error("could not queue a bounce", "error", err)
		return
	}
	n, err := s.blobs.Put(id, bytes.NewReader(raw), int64(len(raw))+1)
	if err != nil {
		s.blobs.Delete(id)
		log.Error("could not spool a bounce", "error", err)
		return
	}
	err = s.db.Enqueue(ctx, &store.Message{
		ID: id, DomainID: m.DomainID, EnvelopeFrom: "", EnvelopeTo: []string{m.EnvelopeFrom},
		Subject: "Undelivered Mail Returned to Sender", SizeBytes: n,
		ReceivedAt: now, ExpiresAt: now.Add(s.cfg.Retention), NextRetryAt: now,
		Direction: store.DirectionOutbound,
	})
	if err != nil {
		s.blobs.Delete(id)
		log.Error("could not queue a bounce", "error", err)
		return
	}
	log.Info("bounce queued", "bounce", id, "recipients", len(failures))
}

func (s *Sender) defer_(ctx context.Context, m *store.Message, reason string) {
	err := s.db.Reschedule(ctx, m.ID, m.Attempts+1, reason,
		s.cfg.RetryBase, s.cfg.RetryMax, time.Now().UTC())
	if err != nil {
		s.log.Error("could not reschedule", "id", m.ID, "error", err)
		return
	}
	s.record(ctx, store.EventMailDeferred, m, map[string]any{"reason": reason})
}

func (s *Sender) destinationPolicy() smtpclient.Option {
	return smtpclient.PublicOnly(!s.cfg.AllowPrivateDestinations)
}

func send(ctx context.Context, d *store.Domain, m *store.Message, body io.Reader, extraHeaders string, policy smtpclient.Option) (recipients, error) {
	client, err := smtpclient.Dial(ctx, d, smtpclient.HelloName(d), policy)
	if err != nil {
		return recipients{}, err
	}
	defer client.Close()
	return transmit(client, m, body, extraHeaders)
}

func (s *Sender) maintain(ctx context.Context) {
	now := time.Now().UTC()

	expired, err := s.db.ExpireOverdue(ctx, now)
	if err != nil {
		s.log.Error("expiry pass failed", "error", err)
	}
	for _, id := range expired {

		s.count.MessagesExpired.Add(1)
		s.log.Warn("message expired before the primary accepted it", "id", id)
		expiredEvent := &store.Event{Type: store.EventMailExpired, QueueID: &id}
		if m, err := s.db.GetMessage(ctx, id); err == nil {
			held := now.Sub(m.ReceivedAt)
			s.bounce(ctx, m, eachRecipient(m.EnvelopeTo, func(rcpt string) dsn.Failure { return dsn.Expired(rcpt, held) }))
			domainID := m.DomainID
			expiredEvent.DomainID = &domainID
			expiredEvent.Data = map[string]any{
				"from": m.EnvelopeFrom, "to": m.EnvelopeTo, "attempts": m.Attempts, "last_error": m.LastError,
			}
		}
		if err := s.blobs.Delete(id); err != nil {
			s.log.Warn("expired body not removed", "id", id, "error", err)
		}
		if err := s.db.RecordEvent(ctx, expiredEvent); err != nil {
			s.log.Warn("expiry event not recorded", "error", err)
		}
		if s.notify != nil {
			s.notify.Notify(store.EventMailExpired, map[string]any{"id": id})
		}
	}

	cutoff := now.Add(-3 * s.cfg.DeliveryTimeout)
	if n, err := s.db.ReleaseOrphanedClaims(ctx, cutoff); err != nil {
		s.log.Error("orphan recovery failed", "error", err)
	} else if n > 0 {
		s.log.Warn("recovered stale delivery claims", "count", n)
	}

	if n, err := s.db.PurgeDelivered(ctx, now.Add(-30*24*time.Hour)); err != nil {
		s.log.Error("purge failed", "error", err)
	} else if n > 0 {
		s.log.Debug("purged old queue history", "rows", n)
	}
	if _, err := s.db.PurgeEvents(ctx, 50000); err != nil {
		s.log.Error("event purge failed", "error", err)
	}
}

func (s *Sender) record(ctx context.Context, typ string, m *store.Message, data map[string]any) {
	domainID := m.DomainID
	id := m.ID
	if err := s.db.RecordEvent(ctx, &store.Event{
		Type: typ, DomainID: &domainID, QueueID: &id, Data: data,
	}); err != nil {
		s.log.Warn("event not recorded", "type", typ, "error", err)
	}
	if s.notify != nil {
		payload := map[string]any{"id": m.ID}
		for k, v := range data {
			payload[k] = v
		}
		s.notify.Notify(typ, payload)
	}
}

func workerID() string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return host + "/" + strconv.Itoa(os.Getpid())
}

func (s *Sender) sealARC(ctx context.Context, d *store.Domain, m *store.Message, body io.Reader) io.Reader {
	if s.db == nil || d == nil {
		return body
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return body
	}
	key, err := s.db.DKIMKeyFor(ctx, d.ID)
	if err != nil || !key.Enabled {
		return bytes.NewReader(raw)
	}
	pem, err := s.blobs.Unseal(key.PrivateKey)
	if err != nil {
		return bytes.NewReader(raw)
	}
	signer, err := dkim.ParsePrivate(pem)
	if err != nil {
		return bytes.NewReader(raw)
	}
	authservID := s.hostname
	if authservID == "" {
		authservID = d.Name
	}
	cv := authres.ARCResult(m.AuthResults)
	if cv != arc.CVPass && cv != arc.CVFail {
		cv = ""
	}
	sealer := arc.NewSealer(d.Name, key.Selector, signer)
	var out bytes.Buffer
	if err := sealer.Seal(&out, bytes.NewReader(raw), authservID, m.AuthResults, cv); err != nil {
		switch {
		case errors.Is(err, arc.ErrUnvalidatedChain):
			s.log.Debug("message already carries an arc chain that was not validated, delivering unsealed", "domain", d.Name)
		case errors.Is(err, arc.ErrFailedChain), errors.Is(err, arc.ErrChainTooLong):
			s.log.Debug("message's arc chain cannot be extended, delivering unsealed", "domain", d.Name, "reason", err)
		default:
			s.log.Warn("arc sealing failed, delivering unsealed", "domain", d.Name, "error", err)
		}
		return bytes.NewReader(raw)
	}
	s.log.Debug("message sealed with arc", "domain", d.Name, "selector", key.Selector, "cv", cv)
	return &out
}

func peer(m *store.Message) string {
	if m.Direction == store.DirectionOutbound {
		return "the receiving server"
	}
	return "primary"
}
