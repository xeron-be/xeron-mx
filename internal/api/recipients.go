package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const maxRecipients = 100000

func validRecipients(domain string, list []string) ([]string, bool) {
	if len(list) > maxRecipients {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, raw := range list {
		addr := store.NormalizeRecipient(raw)
		if addr == "" {
			continue
		}
		at := strings.LastIndex(addr, "@")
		if at <= 0 || addr[at+1:] != domain || strings.ContainsAny(addr, " \t\r\n<>,;") {
			return nil, false
		}
		out = append(out, addr)
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func (s *Server) handleGetRecipients(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	list, err := s.db.DomainRecipients(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrRecipientsReadFailed)
		return
	}
	s.ok(w, http.StatusOK, map[string]any{"recipients": list})
}

func (s *Server) handleSetRecipients(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	var req struct {
		Recipients []string `json:"recipients"`
	}
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	list, valid := validRecipients(d.Name, req.Recipients)
	if !valid {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidRecipient)
		return
	}
	if err := s.db.SetDomainRecipients(r.Context(), d.ID, list); err != nil {
		s.log.Error("set recipients failed", "domain", d.Name, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrRecipientsUpdateFailed)
		return
	}
	s.log.Info("known recipients updated", "domain", d.Name, "count", len(list))
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "recipients_updated", DomainID: &d.ID, UserID: &userFrom(r).ID,
		Data: map[string]any{"domain": d.Name, "count": len(list)},
	})
	s.ok(w, http.StatusOK, map[string]any{"recipients": list})
}
