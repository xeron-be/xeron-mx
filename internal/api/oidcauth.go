package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/xeron-be/xeron-mx/internal/oidc"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	oidcCookie = "xeronmx_oidc"
	oidcPath   = "/api/v1/auth/oidc"

	oidcFlowTTL = 10 * time.Minute
)

type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r,omitempty"`
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const (
	ssoNotConfigured = "not_configured"
	ssoNotReady      = "not_ready"
	ssoState         = "state"
	ssoExchange      = "exchange"
	ssoUnverified    = "unverified"
	ssoNoAccount     = "no_account"
	ssoConflict      = "conflict"
	ssoServer        = "server"
)

func (s *Server) ssoFailed(w http.ResponseWriter, r *http.Request, code string) {
	s.clearOIDCCookie(w)
	http.Redirect(w, r, "/?sso_error="+code, http.StatusSeeOther)
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || !s.oidc.Enabled() {
		s.ssoFailed(w, r, ssoNotConfigured)
		return
	}
	if ready, err := s.oidc.Ready(); !ready {
		s.log.Warn("sso attempted before the provider could be reached", "error", err)
		s.ssoFailed(w, r, ssoNotReady)
		return
	}

	state, err := randomString()
	if err != nil {
		s.ssoFailed(w, r, ssoServer)
		return
	}
	nonce, err := randomString()
	if err != nil {
		s.ssoFailed(w, r, ssoServer)
		return
	}
	verifier := oauth2.GenerateVerifier()

	raw, err := json.Marshal(flowState{State: state, Nonce: nonce, Verifier: verifier})
	if err != nil {
		s.ssoFailed(w, r, ssoServer)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcCookie,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     oidcPath,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secure(),
		MaxAge:   int(oidcFlowTTL.Seconds()),
	})

	target, err := s.oidc.AuthCodeURL(state, nonce, verifier)
	if err != nil {
		s.ssoFailed(w, r, ssoNotReady)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || !s.oidc.Enabled() {
		s.ssoFailed(w, r, ssoNotConfigured)
		return
	}
	ctx := r.Context()

	if reason := r.URL.Query().Get("error"); reason != "" {
		s.log.Warn("the identity provider refused a sign-in",
			"error", reason, "description", r.URL.Query().Get("error_description"))
		s.ssoFailed(w, r, ssoExchange)
		return
	}

	flow, ok := s.readOIDCCookie(r)
	if !ok {
		s.ssoFailed(w, r, ssoState)
		return
	}
	if subtle.ConstantTimeCompare([]byte(flow.State), []byte(r.URL.Query().Get("state"))) != 1 {
		s.log.Warn("sso callback state did not match", "ip", clientIP(r))
		s.ssoFailed(w, r, ssoState)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.ssoFailed(w, r, ssoExchange)
		return
	}

	identity, err := s.oidc.Exchange(ctx, code, flow.Nonce, flow.Verifier)
	switch {
	case errors.Is(err, oidc.ErrEmailUnverified):
		s.log.Warn("sso rejected: the provider did not vouch for the address", "error", err)
		s.ssoFailed(w, r, ssoUnverified)
		return
	case err != nil:
		s.log.Error("sso exchange failed", "error", err)
		s.ssoFailed(w, r, ssoExchange)
		return
	}

	user, failure := s.resolveIdentity(ctx, identity)
	if failure != "" {
		s.ssoFailed(w, r, failure)
		return
	}

	s.clearOIDCCookie(w)
	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("sso: session creation failed", "error", err)
		s.ssoFailed(w, r, ssoServer)
		return
	}

	s.db.TouchLogin(ctx, user.ID)
	s.audit(ctx, r, &store.Event{
		Type: store.EventLogin, UserID: &user.ID,
		Data: map[string]any{"ip": clientIP(r), "method": "oidc", "issuer": identity.Issuer, "by": user.Email},
	})
	s.log.Info("sso login", "email", user.Email, "role", user.Role, "ip", clientIP(r))

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) resolveIdentity(ctx context.Context, id *oidc.Identity) (*store.User, string) {
	user, err := s.db.UserByOIDC(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil:
		if id.Role != "" && id.Role != user.Role {
			if err := s.db.UpdateUserRole(ctx, user.ID, id.Role); err == nil {
				user.Role = id.Role
			}
		}
		return user, ""
	case !errors.Is(err, store.ErrNotFound):
		s.log.Error("sso: identity lookup failed", "error", err)
		return nil, ssoServer
	}

	user, err = s.db.UserByEmail(ctx, id.Email)
	switch {
	case err == nil:
		if user.OIDCSubject != "" && user.OIDCSubject != id.Subject {
			s.log.Error("sso refused: this account is already bound to a different provider identity",
				"email", user.Email, "issuer", user.OIDCIssuer)
			return nil, ssoConflict
		}
		if err := s.db.LinkOIDC(ctx, user.ID, id.Issuer, id.Subject); err != nil {
			s.log.Error("sso: could not link the account", "email", user.Email, "error", err)
			return nil, ssoServer
		}
		s.log.Warn("local account linked to an identity provider",
			"email", user.Email, "issuer", id.Issuer)
		user.OIDCIssuer, user.OIDCSubject = id.Issuer, id.Subject
		if id.Role != "" && id.Role != user.Role {
			if err := s.db.UpdateUserRole(ctx, user.ID, id.Role); err == nil {
				user.Role = id.Role
			}
		}
		return user, ""
	case !errors.Is(err, store.ErrNotFound):
		s.log.Error("sso: account lookup failed", "error", err)
		return nil, ssoServer
	}

	if !s.oidc.MayProvision(id.Email) {
		s.log.Warn("sso refused: no account here and auto-provisioning does not cover this address",
			"email", id.Email)
		return nil, ssoNoAccount
	}

	role := s.oidc.DefaultRole()
	if id.Role != "" {
		role = id.Role
	}
	newID, err := s.db.CreateOIDCUser(ctx, id.Email, role, id.Issuer, id.Subject)
	if err != nil {
		s.log.Error("sso: could not create the account", "email", id.Email, "error", err)
		return nil, ssoServer
	}
	s.log.Warn("account provisioned from the identity provider",
		"email", id.Email, "role", role, "issuer", id.Issuer)

	user, err = s.db.UserByID(ctx, newID)
	if err != nil {
		return nil, ssoServer
	}
	return user, ""
}

func (s *Server) readOIDCCookie(r *http.Request) (*flowState, bool) {
	cookie, err := r.Cookie(oidcCookie)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, false
	}
	var flow flowState
	if err := json.Unmarshal(raw, &flow); err != nil {
		return nil, false
	}
	if flow.State == "" || flow.Nonce == "" || flow.Verifier == "" {
		return nil, false
	}
	return &flow, true
}

func (s *Server) clearOIDCCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: "", Path: oidcPath,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: s.secure(), MaxAge: -1,
	})
}
