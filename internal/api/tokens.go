package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const maxTokenTTL = 365 * 24 * time.Hour

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

func (s *Server) principalForToken(ctx context.Context, presented string) (*store.User, *store.APIToken, error) {
	tok, err := s.db.APITokenByHash(ctx, auth.HashToken(presented))
	if err != nil {
		return nil, nil, err
	}
	if tok.CreatedBy == nil {
		return nil, nil, store.ErrNotFound
	}
	owner, err := s.db.UserByID(ctx, *tok.CreatedBy)
	if err != nil {
		return nil, nil, err
	}

	acting := *owner
	acting.Role = narrowerRole(owner.Role, tok.Role)
	return &acting, tok, nil
}

func narrowerRole(a, b string) string {
	if a == store.RoleAdmin && b == store.RoleAdmin {
		return store.RoleAdmin
	}
	return store.RoleViewer
}

type tokenRequest struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	ExpiresIn string `json:"expires_in"`
}

type tokenView struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Expired    bool       `json:"expired"`
}

func viewToken(t *store.APIToken, now time.Time) tokenView {
	return tokenView{
		ID: t.ID, Name: t.Name, Prefix: t.Prefix, Role: t.Role,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		LastUsedAt: t.LastUsedAt, Expired: t.Expired(now),
	}
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.db.ListAPITokens(r.Context())
	if err != nil {
		s.log.Error("could not list api tokens", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrTokenListFailed)
		return
	}

	now := time.Now().UTC()
	out := make([]tokenView, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, viewToken(t, now))
	}
	s.ok(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	admin := userFrom(r)

	var req tokenRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidName)
		return
	}
	if len(name) > 100 {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidName)
		return
	}

	role := req.Role
	if role == "" {
		role = store.RoleViewer
	}
	if role != store.RoleAdmin && role != store.RoleViewer {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidRole)
		return
	}
	if role == store.RoleAdmin && admin.Role != store.RoleAdmin {
		s.fail(w, r, http.StatusForbidden, ErrTokenRoleTooBroad)
		return
	}

	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidExpiration)
			return
		}
		if d <= 0 {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidExpiration)
			return
		}
		if d > maxTokenTTL {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidExpiration)
			return
		}
		t := time.Now().UTC().Add(d)
		expiresAt = &t
	} else {
		t := time.Now().UTC().Add(maxTokenTTL)
		expiresAt = &t
	}

	token, hash, prefix, err := auth.NewAPIToken()
	if err != nil {
		s.log.Error("could not mint an api token", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrTokenCreateFailed)
		return
	}

	rec := &store.APIToken{
		Name: name, Prefix: prefix, Role: role,
		CreatedBy: &admin.ID, ExpiresAt: expiresAt,
	}
	id, err := s.db.CreateAPIToken(r.Context(), rec, hash)
	if err != nil {
		s.log.Error("could not store an api token", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrTokenCreateFailed)
		return
	}
	rec.ID = id
	rec.CreatedAt = time.Now().UTC()

	s.log.Warn("api token created", "name", name, "role", role, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "api_token_created", UserID: &admin.ID,
		Data: map[string]any{"name": name, "role": role, "prefix": prefix},
	})

	view := viewToken(rec, time.Now().UTC())
	s.ok(w, http.StatusCreated, map[string]any{
		"token":  view,
		"secret": token,
		"notice": "Copy this now. It is stored only as a hash and cannot be shown again.",
	})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidTokenID)
		return
	}
	admin := userFrom(r)

	if err := s.db.DeleteAPIToken(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrTokenNotFound)
			return
		}
		s.log.Error("could not delete an api token", "id", id, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrTokenDeleteFailed)
		return
	}

	s.log.Warn("api token revoked", "id", id, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "api_token_deleted", UserID: &admin.ID,
		Data: map[string]any{"id": id},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": id})
}
