package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/filter"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type filterRequest struct {
	Name     string `json:"name"`
	Field    string `json:"field"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"`
	Enabled  *bool  `json:"enabled"`
	Priority *int   `json:"priority"`
}

func (s *Server) reloadFilters(r *http.Request) {
	if s.filters == nil {
		return
	}
	if err := s.filters.Load(r.Context()); err != nil {
		s.log.Error("filters saved but not reloaded; they take effect on the next sweep",
			"error", err)
	}
}

func filterJSON(f *store.Filter) map[string]any {
	return map[string]any{
		"id": f.ID, "name": f.Name, "field": f.Field,
		"pattern": f.Pattern, "action": f.Action,
		"enabled": f.Enabled, "priority": f.Priority,
		"match_count": f.MatchCount, "last_match_at": f.LastMatchAt,
		"created_at": f.CreatedAt,
	}
}

func (s *Server) handleListFilters(w http.ResponseWriter, r *http.Request) {
	rules, err := s.db.ListFilters(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrFilterReadFailed)
		return
	}
	out := make([]map[string]any, 0, len(rules))
	for _, f := range rules {
		out = append(out, filterJSON(f))
	}
	s.ok(w, http.StatusOK, map[string]any{"filters": out})
}

func (s *Server) filterFromRequest(req *filterRequest, existing *store.Filter) (*store.Filter, string) {
	f := &store.Filter{Enabled: true, Priority: 100}
	if existing != nil {
		f = &store.Filter{
			ID: existing.ID, Name: existing.Name, Field: existing.Field,
			Pattern: existing.Pattern, Action: existing.Action,
			Enabled: existing.Enabled, Priority: existing.Priority,
		}
	}

	if req.Name != "" {
		f.Name = strings.TrimSpace(req.Name)
	}
	if f.Name == "" {
		return nil, ErrInvalidFilter
	}
	if req.Field != "" {
		f.Field = req.Field
	}
	if !store.ValidFilterField(f.Field) {
		return nil, ErrInvalidFilterField
	}
	if req.Pattern != "" {
		f.Pattern = req.Pattern
	}
	if _, err := filter.Compile(f.Pattern); err != nil {
		return nil, ErrInvalidFilter
	}
	if req.Action != "" {
		f.Action = req.Action
	}
	if !store.ValidFilterAction(f.Action) {
		return nil, ErrInvalidFilter
	}
	if req.Priority != nil {
		f.Priority = *req.Priority
	}
	if f.Priority < 0 || f.Priority > 10000 {
		return nil, ErrInvalidFilter
	}
	if req.Enabled != nil {
		f.Enabled = *req.Enabled
	}
	return f, ""
}

func (s *Server) handleCreateFilter(w http.ResponseWriter, r *http.Request) {
	var req filterRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	f, errMsg := s.filterFromRequest(&req, nil)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}

	id, err := s.db.CreateFilter(r.Context(), f)
	if err != nil {
		s.log.Error("create filter failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrFilterCreateFailed)
		return
	}
	f.ID = id
	if stored, err := s.db.FilterByID(r.Context(), id); err == nil {
		f = stored
	}

	s.reloadFilters(r)

	admin := userFrom(r)
	s.log.Info("filter created", "name", f.Name, "action", f.Action, "by", admin.Email)
	s.audit(r.Context(), r, &store.Event{
		Type: "filter_created", UserID: &admin.ID,
		Data: map[string]any{"name": f.Name, "field": f.Field, "action": f.Action},
	})
	s.ok(w, http.StatusCreated, filterJSON(f))
}

func (s *Server) handleUpdateFilter(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidFilterID)
		return
	}
	existing, err := s.db.FilterByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, ErrFilterNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrFilterReadFailed)
		return
	}

	var req filterRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	f, errMsg := s.filterFromRequest(&req, existing)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}
	if err := s.db.UpdateFilter(r.Context(), f); err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrFilterUpdateFailed)
		return
	}
	s.reloadFilters(r)
	s.ok(w, http.StatusOK, filterJSON(f))
}

func (s *Server) handleDeleteFilter(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidFilterID)
		return
	}
	if err := s.db.DeleteFilter(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrFilterNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrFilterDeleteFailed)
		return
	}
	s.reloadFilters(r)

	admin := userFrom(r)
	s.log.Warn("filter deleted", "id", id, "by", admin.Email)
	s.audit(r.Context(), r, &store.Event{
		Type: "filter_deleted", UserID: &admin.ID, Data: map[string]any{"id": id},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": id})
}

type filterTestRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Pattern string   `json:"pattern"`
	Field   string   `json:"field"`
}

func (s *Server) handleTestFilters(w http.ResponseWriter, r *http.Request) {
	var req filterTestRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	msg := filter.Message{From: req.From, To: req.To, Subject: req.Subject}

	if req.Pattern != "" {
		if !store.ValidFilterField(req.Field) {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidFilterField)
			return
		}
		draft := []*store.Filter{{
			ID: 0, Name: "(draft)", Field: req.Field, Pattern: req.Pattern,
			Action: store.FilterQuarantine, Enabled: true,
		}}
		v, err := filter.Test(draft, msg)
		if err != nil {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidFilter)
			return
		}
		s.ok(w, http.StatusOK, map[string]any{
			"matched": v.Action != "",
			"value":   v.Matched,
		})
		return
	}

	rules, err := s.db.ListFilters(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrFilterReadFailed)
		return
	}
	v, err := filter.Test(rules, msg)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidFilter)
		return
	}
	if v.Action == "" {
		s.ok(w, http.StatusOK, map[string]any{"matched": false})
		return
	}
	s.ok(w, http.StatusOK, map[string]any{
		"matched": true,
		"filter":  v.Name,
		"id":      v.FilterID,
		"field":   v.Field,
		"action":  v.Action,
		"value":   v.Matched,
		"reason":  v.Reason(),
	})
}

func (s *Server) handleReleaseMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.lookupMessage(w, r)
	if !ok {
		return
	}
	if err := s.db.Release(r.Context(), m.ID, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusConflict, ErrNotInQuarantine)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrQuarantineReleaseFailed)
		return
	}

	admin := userFrom(r)
	s.log.Warn("message released from quarantine", "id", m.ID, "admin", admin.Email)
	s.audit(r.Context(), r, &store.Event{
		Type: "mail_released", QueueID: &m.ID, DomainID: &m.DomainID, UserID: &admin.ID,
		Data: map[string]any{"from": m.EnvelopeFrom, "to": m.EnvelopeTo,
			"was": m.QuarantineReason},
	})
	s.ok(w, http.StatusOK, map[string]string{
		"released": m.ID,
		"status":   fmt.Sprintf("queued for delivery to domain %d", m.DomainID),
	})
}
