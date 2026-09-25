package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	maxWebhookURLLength = 2000
	maxWebhookEvents    = 64
)

type webhookRequest struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Secret  *string  `json:"secret"`
	Enabled *bool    `json:"enabled"`
}

type webhookView struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	Events        []string   `json:"events"`
	Enabled       bool       `json:"enabled"`
	Signed        bool       `json:"signed"`
	CreatedAt     time.Time  `json:"created_at"`
	LastError     string     `json:"last_error,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
}

func viewWebhook(w *store.Webhook) webhookView {
	events := w.Events
	if events == nil {
		events = []string{}
	}
	return webhookView{
		ID: w.ID, Name: w.Name, URL: w.URL, Events: events,
		Enabled: w.Enabled, Signed: len(w.Secret) > 0,
		CreatedAt: w.CreatedAt, LastError: w.LastError, LastSuccessAt: w.LastSuccessAt,
	}
}

func (s *Server) handleWebhookEventTypes(w http.ResponseWriter, r *http.Request) {
	s.ok(w, http.StatusOK, map[string]any{"categories": store.EventCatalogue()})
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	hooks, err := s.db.ListWebhooks(r.Context())
	if err != nil {
		s.log.Error("could not list webhooks", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookListFailed)
		return
	}
	out := make([]webhookView, 0, len(hooks))
	for _, h := range hooks {
		out = append(out, viewWebhook(h))
	}
	s.ok(w, http.StatusOK, map[string]any{
		"webhooks": out,
		"enabled":  s.hooks != nil && s.hooks.Enabled(),
	})
}

func (s *Server) validateWebhook(req *webhookRequest) (string, []string, string) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return "", nil, ErrInvalidWebhook
	}
	if len(name) > 100 {
		return "", nil, ErrInvalidWebhook
	}

	raw := strings.TrimSpace(req.URL)
	if raw == "" {
		return "", nil, ErrInvalidWebhook
	}
	if len(raw) > maxWebhookURLLength {
		return "", nil, ErrInvalidWebhook
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", nil, ErrInvalidWebhook
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", nil, ErrInvalidWebhook
	}

	if len(req.Events) > maxWebhookEvents {
		return "", nil, ErrInvalidWebhook
	}
	seen := map[string]bool{}
	events := make([]string, 0, len(req.Events))
	for _, e := range req.Events {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		if !store.KnownEventType(e) {
			return "", nil, ErrInvalidWebhook
		}
		seen[e] = true
		events = append(events, e)
	}
	return name, events, ""
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	admin := userFrom(r)

	var req webhookRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	name, events, errMsg := s.validateWebhook(&req)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	secret, plaintext, errMsg := s.sealWebhookSecret(req.Secret)
	if errMsg != "" {
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookCreateFailed)
		return
	}

	hook := &store.Webhook{
		Name: name, URL: strings.TrimSpace(req.URL),
		Events: events, Enabled: enabled, Secret: secret,
	}
	id, err := s.db.CreateWebhook(r.Context(), hook)
	if err != nil {
		s.log.Error("could not create a webhook", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookCreateFailed)
		return
	}
	hook.ID = id
	hook.CreatedAt = time.Now().UTC()

	s.log.Info("webhook created", "name", name, "url", hook.URL, "by", admin.Email)
	s.audit(r.Context(), r, &store.Event{
		Type: store.EventWebhookCreated, UserID: &admin.ID,
		Data: map[string]any{"name": name, "url": hook.URL, "events": events},
	})

	body := map[string]any{"webhook": viewWebhook(hook)}
	if plaintext != "" {
		body["secret"] = plaintext
		body["notice"] = "Copy this signing secret now. It is stored sealed and cannot be shown again."
	}
	s.ok(w, http.StatusCreated, body)
}

func (s *Server) sealWebhookSecret(requested *string) (sealed []byte, plaintext, errMsg string) {
	switch {
	case requested == nil:
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, "", "could not generate a signing secret"
		}
		plaintext = base64.RawURLEncoding.EncodeToString(b)
	case *requested == "":
		return nil, "", ""
	default:
		plaintext = *requested
	}

	sealed, err := s.blobs.Seal([]byte(plaintext))
	if err != nil {
		s.log.Error("could not seal a webhook secret", "error", err)
		return nil, "", "could not protect the signing secret"
	}
	if requested != nil {
		plaintext = ""
	}
	return sealed, plaintext, ""
}

func (s *Server) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidWebhookID)
		return
	}
	admin := userFrom(r)

	existing, err := s.db.Webhook(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrWebhookNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookListFailed)
		return
	}

	var req webhookRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if req.Name == "" {
		req.Name = existing.Name
	}
	if req.URL == "" {
		req.URL = existing.URL
	}
	if req.Events == nil {
		req.Events = existing.Events
	}

	name, events, errMsg := s.validateWebhook(&req)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	updated := &store.Webhook{
		ID: id, Name: name, URL: strings.TrimSpace(req.URL),
		Events: events, Enabled: enabled,
	}
	if err := s.db.UpdateWebhook(r.Context(), updated); err != nil {
		s.log.Error("could not update a webhook", "id", id, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookUpdateFailed)
		return
	}

	var rotated string
	if req.Secret != nil {
		sealed, plaintext, errMsg := s.sealWebhookSecret(req.Secret)
		if errMsg != "" {
			s.fail(w, r, http.StatusInternalServerError, ErrWebhookUpdateFailed)
			return
		}
		if err := s.db.SetWebhookSecret(r.Context(), id, sealed); err != nil {
			s.log.Error("could not rotate a webhook secret", "id", id, "error", err)
			s.fail(w, r, http.StatusInternalServerError, ErrWebhookUpdateFailed)
			return
		}
		rotated = plaintext
		updated.Secret = sealed
	} else {
		updated.Secret = existing.Secret
	}
	updated.CreatedAt = existing.CreatedAt

	s.log.Info("webhook updated", "id", id, "by", admin.Email)
	s.audit(r.Context(), r, &store.Event{
		Type: store.EventWebhookUpdated, UserID: &admin.ID,
		Data: map[string]any{"id": id, "name": name, "enabled": enabled},
	})

	body := map[string]any{"webhook": viewWebhook(updated)}
	if rotated != "" {
		body["secret"] = rotated
		body["notice"] = "Copy this signing secret now. It is stored sealed and cannot be shown again."
	}
	s.ok(w, http.StatusOK, body)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidWebhookID)
		return
	}
	admin := userFrom(r)

	if err := s.db.DeleteWebhook(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrWebhookNotFound)
			return
		}
		s.log.Error("could not delete a webhook", "id", id, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookDeleteFailed)
		return
	}

	s.log.Info("webhook deleted", "id", id, "by", admin.Email)
	s.audit(r.Context(), r, &store.Event{
		Type: store.EventWebhookDeleted, UserID: &admin.ID,
		Data: map[string]any{"id": id},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if s.hooks == nil || !s.hooks.Enabled() {
		s.fail(w, r, http.StatusConflict, ErrWebhookTestFailed)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidWebhookID)
		return
	}

	hook, err := s.db.Webhook(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrWebhookNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrWebhookListFailed)
		return
	}

	code, err := s.hooks.Test(r.Context(), hook)
	if err != nil {
		s.ok(w, http.StatusOK, map[string]any{
			"ok": false, "status": code, "error": err.Error(),
		})
		return
	}
	s.ok(w, http.StatusOK, map[string]any{"ok": true, "status": code})
}

type deliveryView struct {
	ID          int64      `json:"id"`
	WebhookID   int64      `json:"webhook_id"`
	WebhookName string     `json:"webhook_name"`
	Event       string     `json:"event"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	StatusCode  int        `json:"status_code,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	NextAttempt *time.Time `json:"next_attempt_at,omitempty"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

func (s *Server) handleListDeliveries(w http.ResponseWriter, r *http.Request) {
	webhookID := int64(queryInt(r, "webhook_id", 0))
	limit := queryInt(r, "limit", 50)

	rows, err := s.db.ListDeliveries(r.Context(), webhookID, limit)
	if err != nil {
		s.log.Error("could not list webhook deliveries", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrDeliveryLogFailed)
		return
	}

	out := make([]deliveryView, 0, len(rows))
	for _, d := range rows {
		v := deliveryView{
			ID: d.ID, WebhookID: d.WebhookID, WebhookName: d.WebhookName,
			Event: d.EventType, Status: d.Status, Attempts: d.Attempts,
			StatusCode: d.StatusCode, LastError: d.LastError,
			CreatedAt: d.CreatedAt, DeliveredAt: d.DeliveredAt,
		}
		if d.Status == store.DeliveryPending {
			next := d.NextAttemptAt
			v.NextAttempt = &next
		}
		out = append(out, v)
	}
	s.ok(w, http.StatusOK, map[string]any{"deliveries": out})
}
