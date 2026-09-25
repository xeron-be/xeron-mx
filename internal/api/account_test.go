package api

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/totp"
)

const newTestPassword = "a different long passphrase"

func sessionFrom(t *testing.T, a *testAPI, email, password, code string) (*http.Cookie, int, string) {
	t.Helper()
	body := map[string]any{"email": email, "password": password}
	if code != "" {
		body["code"] = code
	}
	rec := a.do(t, "POST", "/api/v1/auth/login", body, nil)
	errCode, _ := decodeBody(t, rec)["error"].(string)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c, rec.Code, errCode
		}
	}
	return nil, rec.Code, errCode
}

func TestChangingThePasswordKeepsThisSessionAndEndsTheOthers(t *testing.T) {
	a := newTestAPI(t)
	current := a.setup(t)
	other := a.login(t, "admin@test.example")

	rec := a.do(t, "POST", "/api/v1/auth/password", map[string]string{
		"current_password": "not the password", "new_password": newTestPassword,
	}, current)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: %d; want 401", rec.Code)
	}
	rec = a.do(t, "POST", "/api/v1/auth/password", map[string]string{
		"current_password": testPassword, "new_password": "short",
	}, current)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("too short: %d; want 400", rec.Code)
	}
	rec = a.do(t, "POST", "/api/v1/auth/password", map[string]string{
		"current_password": testPassword, "new_password": newTestPassword,
	}, current)
	if rec.Code != http.StatusOK {
		t.Fatalf("change returned %d: %s", rec.Code, rec.Body.String())
	}

	if rec := a.do(t, "GET", "/api/v1/auth/me", nil, current); rec.Code != http.StatusOK {
		t.Fatalf("the session that changed the password was logged out (%d)", rec.Code)
	}
	if rec := a.do(t, "GET", "/api/v1/auth/me", nil, other); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another session survived the password change (%d)", rec.Code)
	}
	if c, _, _ := sessionFrom(t, a, "admin@test.example", testPassword, ""); c != nil {
		t.Fatal("the old password still logs in")
	}
	if c, code, _ := sessionFrom(t, a, "admin@test.example", newTestPassword, ""); c == nil {
		t.Fatalf("the new password does not log in (%d)", code)
	}
}

func TestAnAPITokenCannotChangeItsOwnersCredentials(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "ci", store.RoleAdmin)

	for _, path := range []string{"/api/v1/auth/password", "/api/v1/auth/totp/setup"} {
		rec := a.doAuth(t, "POST", path, token, map[string]string{
			"current_password": testPassword, "new_password": newTestPassword, "password": testPassword,
		})
		if rec.Code != http.StatusForbidden || decodeBody(t, rec)["error"] != ErrSessionRequired {
			t.Fatalf("%s through a token: %d %s; want 403 session_required", path, rec.Code, rec.Body.String())
		}
	}
}

func enableTOTP(t *testing.T, a *testAPI, cookie *http.Cookie) (secret string, step int64, recovery []string) {
	t.Helper()
	rec := a.do(t, "POST", "/api/v1/auth/totp/setup", map[string]string{"password": "wrong"}, cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("setup with a wrong password: %d; want 401", rec.Code)
	}
	rec = a.do(t, "POST", "/api/v1/auth/totp/setup", map[string]string{"password": testPassword}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	secret, _ = body["secret"].(string)
	if qr, _ := body["qr_code"].(string); !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatal("setup returned no QR code")
	}
	if uri, _ := body["uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("uri = %q", uri)
	}

	rec = a.do(t, "POST", "/api/v1/auth/totp/enable", map[string]string{"code": "000000"}, cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("enable with a wrong code: %d; want 401", rec.Code)
	}
	step = totp.Step(time.Now())
	code, _ := totp.Code(secret, step)
	rec = a.do(t, "POST", "/api/v1/auth/totp/enable", map[string]string{"code": code}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable returned %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range decodeBody(t, rec)["recovery_codes"].([]any) {
		recovery = append(recovery, c.(string))
	}
	if len(recovery) != totp.RecoveryCodeCount {
		t.Fatalf("%d recovery codes; want %d", len(recovery), totp.RecoveryCodeCount)
	}
	return secret, step, recovery
}

func TestLoginAsksForTheSecondFactorOnceEnabled(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	secret, step, recovery := enableTOTP(t, a, cookie)

	me := decodeBody(t, a.do(t, "GET", "/api/v1/auth/me", nil, cookie))
	if me["totp_enabled"] != true || me["recovery_codes_left"] != float64(totp.RecoveryCodeCount) {
		t.Fatalf("/auth/me = %v", me)
	}

	if c, status, errCode := sessionFrom(t, a, "admin@test.example", testPassword, ""); c != nil ||
		status != http.StatusUnauthorized || errCode != ErrTOTPRequired {
		t.Fatalf("password alone: cookie=%v status=%d error=%s; want 401 totp_required", c != nil, status, errCode)
	}
	if c, status, _ := sessionFrom(t, a, "admin@test.example", "wrong password", "123456"); c != nil ||
		status != http.StatusUnauthorized {
		t.Fatalf("wrong password with a code: status %d", status)
	}
	if c, _, errCode := sessionFrom(t, a, "admin@test.example", testPassword, "000000"); c != nil ||
		errCode != ErrInvalidCredentials {
		t.Fatalf("wrong code: logged in=%v error=%s", c != nil, errCode)
	}

	next, _ := totp.Code(secret, step+1)
	if c, status, _ := sessionFrom(t, a, "admin@test.example", testPassword, next); c == nil {
		t.Fatalf("a valid code did not log in (%d)", status)
	}
	if c, _, _ := sessionFrom(t, a, "admin@test.example", testPassword, next); c != nil {
		t.Fatal("the same code logged in twice")
	}
	earlier, _ := totp.Code(secret, step)
	if c, _, _ := sessionFrom(t, a, "admin@test.example", testPassword, earlier); c != nil {
		t.Fatal("a code older than the last one used was accepted")
	}

	typed := strings.ToUpper(strings.ReplaceAll(recovery[0], "-", ""))
	if c, _, _ := sessionFrom(t, a, "admin@test.example", testPassword, typed); c == nil {
		t.Fatal("a recovery code did not log in")
	}
	if c, _, _ := sessionFrom(t, a, "admin@test.example", testPassword, recovery[0]); c != nil {
		t.Fatal("a recovery code worked twice")
	}
	me = decodeBody(t, a.do(t, "GET", "/api/v1/auth/me", nil, cookie))
	if me["recovery_codes_left"] != float64(totp.RecoveryCodeCount-1) {
		t.Fatalf("recovery_codes_left = %v", me["recovery_codes_left"])
	}
}

func TestDisablingTheSecondFactorNeedsPasswordAndCode(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	_, _, recovery := enableTOTP(t, a, cookie)

	rec := a.do(t, "POST", "/api/v1/auth/totp/disable", map[string]string{
		"password": testPassword, "code": "000000",
	}, cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong code: %d", rec.Code)
	}
	rec = a.do(t, "POST", "/api/v1/auth/totp/disable", map[string]string{
		"password": "wrong", "code": recovery[1],
	}, cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong password: %d", rec.Code)
	}

	rec = a.do(t, "POST", "/api/v1/auth/totp/recovery-codes", map[string]string{
		"password": testPassword, "code": recovery[2],
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew recovery codes: %d %s", rec.Code, rec.Body.String())
	}
	renewed := decodeBody(t, rec)["recovery_codes"].([]any)
	rec = a.do(t, "POST", "/api/v1/auth/totp/disable", map[string]string{
		"password": testPassword, "code": recovery[3],
	}, cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("an old recovery code still worked after renewal")
	}

	rec = a.do(t, "POST", "/api/v1/auth/totp/disable", map[string]string{
		"password": testPassword, "code": renewed[0].(string),
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable returned %d: %s", rec.Code, rec.Body.String())
	}
	if c, _, _ := sessionFrom(t, a, "admin@test.example", testPassword, ""); c == nil {
		t.Fatal("the password alone does not log in after disabling the second factor")
	}
}

func TestAnAdminResetsAnotherAccountsSecondFactorButNotTheirOwn(t *testing.T) {
	a := newTestAPI(t)
	admin := a.setup(t)
	rec := a.do(t, "POST", "/api/v1/users", map[string]any{
		"email": "ops@test.example", "role": store.RoleOperator, "password": testPassword,
	}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}
	opsID := int64(decodeBody(t, rec)["id"].(float64))
	ops := a.login(t, "ops@test.example")
	enableTOTP(t, a, ops)

	if c, _, errCode := sessionFrom(t, a, "ops@test.example", testPassword, ""); c != nil || errCode != ErrTOTPRequired {
		t.Fatal("the operator's second factor is not enforced")
	}

	adminID := int64(decodeBody(t, a.do(t, "GET", "/api/v1/auth/me", nil, admin))["id"].(float64))
	rec = a.do(t, "PATCH", "/api/v1/users/"+strconv.FormatInt(adminID, 10), map[string]any{"reset_totp": true}, admin)
	if rec.Code != http.StatusBadRequest || decodeBody(t, rec)["error"] != ErrOwnTOTPReset {
		t.Fatalf("admin reset their own second factor: %d %s", rec.Code, rec.Body.String())
	}

	rec = a.do(t, "PATCH", "/api/v1/users/"+strconv.FormatInt(opsID, 10), map[string]any{"reset_totp": true}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset returned %d: %s", rec.Code, rec.Body.String())
	}
	if c, status, _ := sessionFrom(t, a, "ops@test.example", testPassword, ""); c == nil {
		t.Fatalf("the operator still needs a code after the reset (%d)", status)
	}

	rec = a.do(t, "PATCH", "/api/v1/users/"+strconv.FormatInt(opsID, 10), map[string]any{"reset_totp": true}, ops)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an operator reached the admin reset: %d", rec.Code)
	}
}
