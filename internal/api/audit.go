package api

import (
	"context"
	"net/http"

	"github.com/xeron-be/xeron-mx/internal/store"
)

func (s *Server) audit(ctx context.Context, r *http.Request, e *store.Event) error {
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	if u := userFrom(r); u != nil {
		if e.UserID == nil {
			id := u.ID
			e.UserID = &id
		}
		if _, set := e.Data["by"]; !set {
			e.Data["by"] = u.Email
		}
	}
	if tok := tokenFrom(r); tok != nil {
		e.Data["via_token"] = tok.Name
	}
	if _, set := e.Data["ip"]; !set {
		e.Data["ip"] = clientIP(r)
	}
	err := s.db.RecordEvent(ctx, e)
	if err != nil {
		s.log.Warn("event not recorded", "type", e.Type, "error", err)
	}
	return err
}
