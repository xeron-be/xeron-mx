package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/totp"
)

const (
	EventPasswordChanged  = "password_changed"
	EventTOTPEnabled      = "totp_enabled"
	EventTOTPDisabled     = "totp_disabled"
	EventTOTPReset        = "totp_reset"
	EventRecoveryCodeUsed = "totp_recovery_code_used"
	EventRecoveryRenewed  = "totp_recovery_codes_renewed"
)

func (s *Server) accountGuard(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	if tokenFrom(r) != nil {
		s.fail(w, r, http.StatusForbidden, ErrSessionRequired)
		return nil, false
	}
	ip := clientIP(r)
	if !s.limiter.Allow(ip) {
		s.log.Warn("login rate limit hit", "ip", ip)
		s.fail(w, r, http.StatusTooManyRequests, ErrRateLimited)
		return nil, false
	}
	u := userFrom(r)
	if !u.HasPassword() {
		s.fail(w, r, http.StatusBadRequest, ErrSSOAccount)
		return nil, false
	}
	return u, true
}

func (s *Server) passwordMatches(u *store.User, password string) bool {
	if len(password) > auth.MaxPasswordBytes {
		return false
	}
	ok, err := auth.VerifyPassword(password, u.PasswordHash)
	if err != nil {
		s.log.Error("account: hash verification failed", "error", err)
	}
	return err == nil && ok
}

func (s *Server) wrongPassword(w http.ResponseWriter, r *http.Request, u *store.User) {
	s.log.Warn("failed login", "email", u.Email, "ip", clientIP(r), "during", "account change")
	s.fail(w, r, http.StatusUnauthorized, ErrInvalidCredentials)
}

func (s *Server) record(ctx context.Context, typ string, u *store.User, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["email"] = u.Email
	s.db.RecordEvent(ctx, &store.Event{Type: typ, UserID: &u.ID, Data: data})
}

type changePasswordReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.accountGuard(w, r)
	if !ok {
		return
	}
	var req changePasswordReq
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if !s.passwordMatches(u, req.CurrentPassword) {
		s.wrongPassword(w, r, u)
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidPassword)
		return
	}
	if req.NewPassword == req.CurrentPassword {
		s.fail(w, r, http.StatusBadRequest, ErrPasswordUnchanged)
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	if err := s.db.UpdatePassword(r.Context(), u.ID, hash); err != nil {
		s.log.Error("update password failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if err := s.db.DeleteOtherSessions(r.Context(), u.ID, auth.HashToken(cookie.Value)); err != nil {
			s.log.Error("revoke other sessions failed", "error", err)
		}
	}
	s.limiter.Reset(clientIP(r))
	s.record(r.Context(), EventPasswordChanged, u, nil)
	s.log.Info("password changed", "email", u.Email, "ip", clientIP(r))
	s.ok(w, http.StatusOK, map[string]any{"changed": true})
}

type passwordReq struct {
	Password string `json:"password"`
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u, ok := s.accountGuard(w, r)
	if !ok {
		return
	}
	var req passwordReq
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if u.TOTPEnabled {
		s.fail(w, r, http.StatusConflict, ErrTOTPAlreadyEnabled)
		return
	}
	if !s.passwordMatches(u, req.Password) {
		s.wrongPassword(w, r, u)
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	sealed, err := s.blobs.Seal([]byte(secret))
	if err != nil {
		s.log.Error("seal totp secret failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	if err := s.db.SetPendingTOTP(r.Context(), u.ID, base64.StdEncoding.EncodeToString(sealed)); err != nil {
		s.log.Error("store pending totp failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	uri := totp.URI(s.totpIssuer(), u.Email, secret)
	png, err := totp.QRCodePNG(uri)
	if err != nil {
		s.log.Error("qr code failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	s.limiter.Reset(clientIP(r))
	s.ok(w, http.StatusOK, map[string]any{
		"secret":  secret,
		"uri":     uri,
		"qr_code": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (s *Server) totpIssuer() string {
	if s.smtp.Hostname != "" {
		return "XeronMX (" + s.smtp.Hostname + ")"
	}
	return "XeronMX"
}

func (s *Server) totpSecret(u *store.User) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(u.TOTPSecret)
	if err != nil || len(sealed) == 0 {
		return "", errors.New("no totp secret")
	}
	plain, err := s.blobs.Unseal(sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

type codeReq struct {
	Code string `json:"code"`
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	u, ok := s.accountGuard(w, r)
	if !ok {
		return
	}
	var req codeReq
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if u.TOTPEnabled {
		s.fail(w, r, http.StatusConflict, ErrTOTPAlreadyEnabled)
		return
	}
	secret, err := s.totpSecret(u)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrTOTPSetupRequired)
		return
	}
	step, valid := totp.Verify(secret, req.Code, time.Now(), 0)
	if !valid {
		s.fail(w, r, http.StatusUnauthorized, ErrInvalidTOTPCode)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	if err := s.db.EnableTOTP(r.Context(), u.ID, step, hashes); err != nil {
		s.log.Error("enable totp failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	s.limiter.Reset(clientIP(r))
	s.record(r.Context(), EventTOTPEnabled, u, nil)
	s.log.Info("two-factor authentication enabled", "email", u.Email)
	s.ok(w, http.StatusOK, map[string]any{"enabled": true, "recovery_codes": codes})
}

func newRecoveryCodes() (codes, hashes []string, err error) {
	codes, err = totp.NewRecoveryCodes()
	if err != nil {
		return nil, nil, err
	}
	hashes = make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = totp.HashRecoveryCode(c)
	}
	return codes, hashes, nil
}

type confirmReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) confirmIdentity(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	u, ok := s.accountGuard(w, r)
	if !ok {
		return nil, false
	}
	var req confirmReq
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return nil, false
	}
	if !u.TOTPEnabled {
		s.fail(w, r, http.StatusBadRequest, ErrTOTPNotEnabled)
		return nil, false
	}
	if !s.passwordMatches(u, req.Password) {
		s.wrongPassword(w, r, u)
		return nil, false
	}
	if !s.secondFactorValid(r.Context(), u, req.Code) {
		s.fail(w, r, http.StatusUnauthorized, ErrInvalidTOTPCode)
		return nil, false
	}
	s.limiter.Reset(clientIP(r))
	return u, true
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u, ok := s.confirmIdentity(w, r)
	if !ok {
		return
	}
	if err := s.db.DisableTOTP(r.Context(), u.ID); err != nil {
		s.log.Error("disable totp failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	s.record(r.Context(), EventTOTPDisabled, u, nil)
	s.log.Warn("two-factor authentication disabled", "email", u.Email, "ip", clientIP(r))
	s.ok(w, http.StatusOK, map[string]any{"enabled": false})
}

func (s *Server) handleTOTPRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u, ok := s.confirmIdentity(w, r)
	if !ok {
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	if err := s.db.ReplaceRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		s.log.Error("renew recovery codes failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrInternal)
		return
	}
	s.record(r.Context(), EventRecoveryRenewed, u, nil)
	s.ok(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) secondFactorValid(ctx context.Context, u *store.User, code string) bool {
	if totp.LooksLikeCode(code) {
		secret, err := s.totpSecret(u)
		if err != nil {
			s.log.Error("totp secret unreadable", "email", u.Email, "error", err)
			return false
		}
		step, ok := totp.Verify(secret, code, time.Now(), u.TOTPLastStep)
		if !ok {
			return false
		}
		consumed, err := s.db.ConsumeTOTPStep(ctx, u.ID, step)
		if err != nil {
			s.log.Error("consume totp step failed", "error", err)
		}
		return consumed
	}
	if totp.NormalizeRecoveryCode(code) == "" {
		return false
	}
	used, err := s.db.ConsumeRecoveryCode(ctx, u.ID, totp.HashRecoveryCode(code))
	if err != nil {
		s.log.Error("consume recovery code failed", "error", err)
		return false
	}
	if used {
		left, _ := s.db.RecoveryCodesLeft(ctx, u.ID)
		s.record(ctx, EventRecoveryCodeUsed, u, map[string]any{"left": left})
		s.log.Warn("recovery code used", "email", u.Email, "left", left)
	}
	return used
}
