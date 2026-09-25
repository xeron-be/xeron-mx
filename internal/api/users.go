package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type userJSON struct {
	ID             int64      `json:"id"`
	Email          string     `json:"email"`
	Role           string     `json:"role"`
	AllowedDomains []string   `json:"allowed_domains"`
	HasPassword    bool       `json:"has_password"`
	TOTPEnabled    bool       `json:"totp_enabled"`
	IsSSO          bool       `json:"is_sso"`
	CreatedAt      time.Time  `json:"created_at"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
}

func renderUser(u *store.User) userJSON {
	allowed := u.AllowedDomains
	if allowed == nil {
		allowed = []string{}
	}
	return userJSON{
		ID:             u.ID,
		Email:          u.Email,
		Role:           u.Role,
		AllowedDomains: allowed,
		HasPassword:    u.HasPassword(),
		TOTPEnabled:    u.TOTPEnabled,
		IsSSO:          u.FromDirectory(),
		CreatedAt:      u.CreatedAt,
		LastLoginAt:    u.LastLoginAt,
	}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		s.log.Error("list users failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrUserListFailed)
		return
	}

	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, renderUser(u))
	}
	s.ok(w, http.StatusOK, map[string]any{"users": out})
}

type createUserReq struct {
	Email          string   `json:"email"`
	Role           string   `json:"role"`
	Password       string   `json:"password"`
	AllowedDomains []string `json:"allowed_domains"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidEmail)
		return
	}

	if req.Role == "" {
		req.Role = store.RoleViewer
	}
	if req.Role != store.RoleAdmin && req.Role != store.RoleOperator && req.Role != store.RoleViewer {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidRole)
		return
	}

	existing, err := s.db.UserByEmail(r.Context(), req.Email)
	if err == nil && existing != nil {
		s.fail(w, r, http.StatusConflict, ErrUserExists)
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("lookup user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	var passwordHash string
	if req.Password != "" {
		if len(req.Password) < 8 {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidPassword)
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			s.log.Error("hash password failed", "error", err)
			s.fail(w, r, http.StatusInternalServerError, ErrUserCreationFailed)
			return
		}
		passwordHash = hash
	}

	id, err := s.db.CreateUser(r.Context(), req.Email, passwordHash, req.Role, req.AllowedDomains)
	if err != nil {
		s.log.Error("create user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrUserCreationFailed)
		return
	}

	created, err := s.db.UserByID(r.Context(), id)
	if err != nil {
		s.log.Error("fetch created user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	current := userFrom(r)
	var currentID *int64
	if current != nil {
		currentID = &current.ID
	}
	s.db.RecordEvent(r.Context(), &store.Event{
		Type:   "user_created",
		UserID: currentID,
		Data:   map[string]any{"user_id": id, "email": created.Email, "role": created.Role, "allowed_domains": created.AllowedDomains},
	})
	s.ok(w, http.StatusCreated, renderUser(created))
}

type updateUserReq struct {
	Role           string    `json:"role"`
	AllowedDomains *[]string `json:"allowed_domains"`
	ResetTOTP      bool      `json:"reset_totp"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidUserID)
		return
	}

	var req updateUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}

	target, err := s.db.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, ErrUserNotFound)
		return
	} else if err != nil {
		s.log.Error("find user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	newRole := target.Role
	if req.Role != "" {
		if req.Role != store.RoleAdmin && req.Role != store.RoleOperator && req.Role != store.RoleViewer {
			s.fail(w, r, http.StatusBadRequest, ErrInvalidRole)
			return
		}
		newRole = req.Role
	}

	allowed := target.AllowedDomains
	if req.AllowedDomains != nil {
		allowed = *req.AllowedDomains
	}

	current := userFrom(r)
	if current != nil && current.ID == id && newRole != store.RoleAdmin {
		s.fail(w, r, http.StatusBadRequest, ErrCannotDeleteSelf)
		return
	}

	if req.ResetTOTP && current != nil && current.ID == id {
		s.fail(w, r, http.StatusBadRequest, ErrOwnTOTPReset)
		return
	}
	if req.ResetTOTP && target.TOTPEnabled {
		if err := s.db.DisableTOTP(r.Context(), id); err != nil {
			s.log.Error("reset totp failed", "error", err)
			s.fail(w, r, http.StatusInternalServerError, ErrUserUpdateFailed)
			return
		}
		var by *int64
		if current != nil {
			by = &current.ID
		}
		s.db.RecordEvent(r.Context(), &store.Event{
			Type: EventTOTPReset, UserID: by, Data: map[string]any{"user_id": id, "email": target.Email},
		})
		s.log.Warn("two-factor authentication reset by an admin", "email", target.Email)
	}

	err = s.db.UpdateUserScope(r.Context(), id, newRole, allowed)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, ErrUserNotFound)
		return
	case errors.Is(err, store.ErrLastAdmin):
		s.fail(w, r, http.StatusBadRequest, ErrLastAdmin)
		return
	case err != nil:
		s.log.Error("update user scope failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrUserUpdateFailed)
		return
	}

	updated, err := s.db.UserByID(r.Context(), id)
	if err != nil {
		s.log.Error("fetch updated user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	var currentID *int64
	if current != nil {
		currentID = &current.ID
	}
	s.db.RecordEvent(r.Context(), &store.Event{
		Type:   "user_updated",
		UserID: currentID,
		Data:   map[string]any{"user_id": id, "email": updated.Email, "role": updated.Role, "allowed_domains": updated.AllowedDomains},
	})
	s.ok(w, http.StatusOK, renderUser(updated))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidUserID)
		return
	}

	current := userFrom(r)
	if current != nil && current.ID == id {
		s.fail(w, r, http.StatusBadRequest, ErrCannotDeleteSelf)
		return
	}

	target, err := s.db.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, ErrUserNotFound)
		return
	} else if err != nil {
		s.log.Error("find user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}

	err = s.db.DeleteUser(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, ErrUserNotFound)
		return
	case errors.Is(err, store.ErrLastAdmin):
		s.fail(w, r, http.StatusBadRequest, ErrLastAdmin)
		return
	case err != nil:
		s.log.Error("delete user failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrUserDeleteFailed)
		return
	}

	var currentID *int64
	if current != nil {
		currentID = &current.ID
	}
	s.db.RecordEvent(r.Context(), &store.Event{
		Type:   "user_deleted",
		UserID: currentID,
		Data:   map[string]any{"user_id": id, "email": target.Email},
	})
	s.ok(w, http.StatusOK, map[string]bool{"ok": true})
}
