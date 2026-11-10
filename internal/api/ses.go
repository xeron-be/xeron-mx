package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/xeron-be/xeron-mx/internal/ses"
	"github.com/xeron-be/xeron-mx/internal/store"
)

// sesUnknown is a domain the manager has not looked at yet: just added, or
// SES integration only now turned on.
const sesUnknown = "unknown"

func (s *Server) handleSESStatus(w http.ResponseWriter, r *http.Request) {
	if s.ses == nil {
		s.ok(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	out := map[string]any{
		"enabled":       true,
		"region":        s.ses.Region(),
		"bounce_sender": s.ses.BounceSender(),
	}
	if s.sending != nil {
		out["events"] = s.sending.Status()
		out["protection"] = protectionJSON(s.sending)
	}
	s.ok(w, http.StatusOK, out)
}

func (s *Server) handleGetSES(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	if s.ses == nil {
		s.ok(w, http.StatusOK, map[string]any{"enabled": false, "domain": d.Name})
		return
	}
	row, err := s.db.SESIdentityFor(r.Context(), d.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("read ses identity failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSESReadFailed)
		return
	}
	s.ok(w, http.StatusOK, s.sesJSON(r.Context(), d, row))
}

func (s *Server) handleCheckSES(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	if s.ses == nil {
		s.fail(w, r, http.StatusConflict, ErrSESDisabled)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	row, err := s.ses.Check(ctx, d)
	if err != nil {
		s.log.Error("ses check failed", "domain", d.Name, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSESCheckFailed)
		return
	}
	s.ok(w, http.StatusOK, s.sesJSON(r.Context(), d, row))
}

func (s *Server) sesJSON(ctx context.Context, d *store.Domain, row *store.SESIdentity) map[string]any {
	out := map[string]any{
		"enabled": true,
		"domain":  d.Name,
		"region":  s.ses.Region(),
		"status":  sesUnknown,
		"records": []map[string]string{},
	}
	if row == nil {
		return out
	}
	records := make([]map[string]string, 0, len(row.DKIMTokens))
	for _, token := range row.DKIMTokens {
		records = append(records, map[string]string{
			"type":  "CNAME",
			"name":  token + "._domainkey." + row.Identity,
			"value": token + ".dkim.amazonses.com",
		})
	}
	out["identity"] = row.Identity
	out["inherited"] = row.Inherited
	out["managed"] = row.Managed
	out["status"] = row.Status
	out["records"] = records
	out["last_error"] = row.LastError
	out["checked_at"] = row.CheckedAt

	_, deps, err := s.ses.Deletable(ctx, d)
	out["deletable"] = err == nil
	if deps == nil {
		deps = []string{}
	}
	out["dependents"] = deps
	return out
}

// deleteSESIdentity returns an error code and HTTP status, or "" once done.
func (s *Server) deleteSESIdentity(ctx context.Context, r *http.Request, d *store.Domain) (string, int) {
	if s.ses == nil {
		return ErrSESDisabled, http.StatusConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	row, _, _ := s.ses.Deletable(ctx, d)
	err := s.ses.DeleteIdentity(ctx, d)
	switch {
	case err == nil:
	case errors.Is(err, ses.ErrNotManaged), errors.Is(err, store.ErrNotFound):
		return ErrSESIdentityNotManaged, http.StatusConflict
	case errors.Is(err, ses.ErrInUse):
		return ErrSESIdentityInUse, http.StatusConflict
	default:
		s.log.Error("ses identity delete failed", "domain", d.Name, "error", err)
		return ErrSESDeleteFailed, http.StatusBadGateway
	}
	identity := d.Name
	if row != nil {
		identity = row.Identity
	}
	s.log.Warn("ses identity deleted", "identity", identity)
	s.audit(ctx, r, &store.Event{
		Type: store.EventSESDeleted, UserID: &userFrom(r).ID,
		Data: map[string]any{"name": d.Name, "identity": identity, "region": s.ses.Region()},
	})
	return "", 0
}
