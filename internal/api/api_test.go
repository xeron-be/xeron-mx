package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const testPassword = "correct horse battery staple"

type testAPI struct {
	*Server
	db      *store.DB
	handler http.Handler
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("blob.Open: %v", err)
	}

	cfg := config.Default()
	cfg.SMTP.Hostname = "mx2.test.example"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	collector := metrics.New(db, &metrics.Counters{}, "", log)
	s := New(cfg.HTTP, cfg.SMTP, cfg.Queue, db, blobs, log, collector)
	return &testAPI{Server: s, db: db, handler: s.routes()}
}

func (a *testAPI) do(t *testing.T, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "192.0.2.10:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

func (a *testAPI) setup(t *testing.T) *http.Cookie {
	t.Helper()
	rec := a.do(t, "POST", "/api/v1/setup", map[string]string{
		"email": "admin@test.example", "password": testPassword,
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup returned %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("setup did not return a session cookie")
	return nil
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return out
}

func TestSetupStatusBeforeAndAfter(t *testing.T) {
	a := newTestAPI(t)

	rec := a.do(t, "GET", "/api/v1/setup", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if needs := decodeBody(t, rec)["needs_setup"]; needs != true {
		t.Fatalf("needs_setup = %v on a fresh instance, want true", needs)
	}

	a.setup(t)

	rec = a.do(t, "GET", "/api/v1/setup", nil, nil)
	if needs := decodeBody(t, rec)["needs_setup"]; needs != false {
		t.Fatalf("needs_setup = %v after setup, want false", needs)
	}
}

func TestSetupClosesAfterFirstAccount(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	rec := a.do(t, "POST", "/api/v1/setup", map[string]string{
		"email": "attacker@evil.example", "password": "another long password",
	}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("SECURITY: second setup returned %d, want 409", rec.Code)
	}
	if n, _ := a.db.CountUsers(context.Background()); n != 1 {
		t.Fatalf("SECURITY: %d accounts exist after a second setup, want 1", n)
	}
}

func TestSetupRejectsWeakPassword(t *testing.T) {
	a := newTestAPI(t)
	rec := a.do(t, "POST", "/api/v1/setup", map[string]string{
		"email": "admin@test.example", "password": "short",
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("accepted a 5-character password (status %d)", rec.Code)
	}
	if n, _ := a.db.CountUsers(context.Background()); n != 0 {
		t.Fatal("an account was created despite the rejected password")
	}
}

func TestSetupRejectsInvalidEmail(t *testing.T) {
	a := newTestAPI(t)
	rec := a.do(t, "POST", "/api/v1/setup", map[string]string{
		"email": "not-an-email", "password": testPassword,
	}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("accepted an invalid email (status %d)", rec.Code)
	}
}

func TestEveryProtectedRouteRefusesAnonymous(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	routes := []struct{ method, path string }{
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/domains"},
		{"GET", "/api/v1/domains/1"},
		{"GET", "/api/v1/domains/1/dns"},
		{"GET", "/api/v1/queue"},
		{"GET", "/api/v1/queue/abc"},
		{"GET", "/api/v1/queue/abc/raw"},
		{"GET", "/api/v1/events"},
		{"GET", "/api/v1/live"},
		{"GET", "/api/v1/auth/me"},
		{"POST", "/api/v1/auth/logout"},
		{"POST", "/api/v1/domains"},
		{"PATCH", "/api/v1/domains/1"},
		{"DELETE", "/api/v1/domains/1"},
		{"POST", "/api/v1/domains/1/test"},
		{"POST", "/api/v1/queue/abc/retry"},
		{"DELETE", "/api/v1/queue/abc"},
		{"GET", "/api/v1/smtp-users"},
		{"POST", "/api/v1/smtp-users"},
		{"PATCH", "/api/v1/smtp-users/1"},
		{"DELETE", "/api/v1/smtp-users/1"},
		{"GET", "/api/v1/domains/1/dmarc"},
		{"POST", "/api/v1/domains/1/dmarc/check"},
	}
	for _, rt := range routes {
		rec := a.do(t, rt.method, rt.path, nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("SECURITY: %s %s returned %d without a session, want 401",
				rt.method, rt.path, rec.Code)
		}
	}
}

func TestLoginAndSessionLifecycle(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	rec := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
		"email": "admin@test.example", "password": testPassword,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", rec.Code, rec.Body.String())
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login set no session cookie")
	}
	if !cookie.HttpOnly {
		t.Error("SECURITY: session cookie is not HttpOnly, so XSS could steal it")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie has no SameSite protection")
	}

	if rec := a.do(t, "GET", "/api/v1/auth/me", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("authenticated request returned %d", rec.Code)
	}

	if rec := a.do(t, "POST", "/api/v1/auth/logout", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("logout returned %d", rec.Code)
	}

	if rec := a.do(t, "GET", "/api/v1/auth/me", nil, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: session still works after logout (status %d)", rec.Code)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	rec := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
		"email": "admin@test.example", "password": "wrong password entirely",
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password returned %d, want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("SECURITY: a session cookie was issued for a failed login")
		}
	}
}

func TestLoginDoesNotRevealWhetherAccountExists(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	unknown := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
		"email": "nobody@test.example", "password": testPassword,
	}, nil)
	wrong := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
		"email": "admin@test.example", "password": "wrong password entirely",
	}, nil)

	if unknown.Code != wrong.Code {
		t.Errorf("status differs: unknown account %d, wrong password %d", unknown.Code, wrong.Code)
	}
	if unknown.Body.String() != wrong.Body.String() {
		t.Errorf("body differs:\n unknown account: %s\n wrong password:  %s",
			unknown.Body.String(), wrong.Body.String())
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	var limited bool
	for i := 0; i < loginMaxTries+3; i++ {
		rec := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
			"email": "admin@test.example", "password": "wrong password entirely",
		}, nil)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("SECURITY: %d failed logins in a row were never throttled", loginMaxTries+3)
	}
}

func TestForgedSessionCookieIsRejected(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	forged := &http.Cookie{Name: sessionCookie, Value: "definitely-not-a-real-token"}
	if rec := a.do(t, "GET", "/api/v1/status", nil, forged); rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: forged cookie accepted (status %d)", rec.Code)
	}
}

func TestSessionTokenIsNotStoredInPlaintext(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	var count int
	err := a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, cookie.Value).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("SECURITY: the raw session token is stored in the database")
	}
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`,
		auth.HashToken(cookie.Value)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("the session hash was not stored")
	}
}

func TestViewerCannotMutate(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	viewerID, err := a.db.CreateUser(context.Background(), "viewer@test.example", hash, store.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	token, tokenHash, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.db.CreateSession(context.Background(), tokenHash, viewerID, config.Default().HTTP.SessionTTL, "test"); err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: sessionCookie, Value: token}

	if rec := a.do(t, "GET", "/api/v1/status", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("viewer cannot read status: %d", rec.Code)
	}

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: viewer created a domain (status %d)", rec.Code)
	}
}

func TestDomainCreateAndValidation(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "Example.COM", "primary_host": "mail.example.com",
	}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["name"] != "example.com" {
		t.Errorf("name = %v, want it lowercased", body["name"])
	}

	if body["primary_tls"] != "opportunistic" {
		t.Errorf("primary_tls = %v, want opportunistic by default", body["primary_tls"])
	}

	rec = a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate domain returned %d, want 409", rec.Code)
	}

	bad := []map[string]any{
		{"name": "", "primary_host": "mail.example.com"},
		{"name": "notadomain", "primary_host": "mail.example.com"},
		{"name": "ok.example", "primary_host": ""},
		{"name": "ok.example", "primary_host": "mail.ok.example", "primary_port": 70000},
		{"name": "ok.example", "primary_host": "mail.ok.example", "primary_tls": "maybe"},
		{"name": "ok.example", "primary_host": "mail.ok.example", "retention_hours": 99999},
	}
	for _, payload := range bad {
		if rec := a.do(t, "POST", "/api/v1/domains", payload, cookie); rec.Code != http.StatusBadRequest {
			t.Errorf("payload %v returned %d, want 400", payload, rec.Code)
		}
	}
}

func TestDomainRejectsSelfAsPrimary(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mx2.test.example",
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("accepted itself as the primary (status %d)", rec.Code)
	}
}

func TestDeleteDomainGuardsQueuedMail(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	ctx := context.Background()

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	domainID := int64(decodeBody(t, rec)["id"].(float64))

	now := timeNow()
	if err := a.db.Enqueue(ctx, &store.Message{
		ID: "abc123", DomainID: domainID,
		EnvelopeFrom: "a@b.example", EnvelopeTo: []string{"c@example.com"},
		SizeBytes: 10, ReceivedAt: now, ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if rec := a.do(t, "DELETE", "/api/v1/domains/"+itoa(domainID), nil, cookie); rec.Code != http.StatusConflict {
		t.Fatalf("deleted a domain with queued mail without confirmation (status %d)", rec.Code)
	}
	if rec := a.do(t, "DELETE", "/api/v1/domains/"+itoa(domainID)+"?force=true", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("forced delete returned %d", rec.Code)
	}
}

func TestDomainCannotBeRenamed(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	domainID := int64(decodeBody(t, rec)["id"].(float64))

	rec = a.do(t, "PATCH", "/api/v1/domains/"+itoa(domainID), map[string]any{
		"name": "other.example",
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rename returned %d, want 400 — queued mail would be orphaned", rec.Code)
	}
}

func TestDomainDNSRecords(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	domainID := int64(decodeBody(t, rec)["id"].(float64))

	rec = a.do(t, "GET", "/api/v1/domains/"+itoa(domainID)+"/dns", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("dns returned %d", rec.Code)
	}
	body := decodeBody(t, rec)
	records, ok := body["records"].([]any)
	if !ok || len(records) < 2 {
		t.Fatalf("expected at least an MX and an A record, got %v", body["records"])
	}
	mx := records[0].(map[string]any)
	if mx["type"] != "MX" || mx["priority"] != "20" {
		t.Errorf("first record should be the MX at priority 20, got %v", mx)
	}
	if checklist, ok := body["checklist"].([]any); !ok || len(checklist) == 0 {
		t.Error("the DNS answer carries no checklist, which is the part people get wrong")
	}
}

func TestQueueEndpointsAndRawAudit(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	ctx := context.Background()

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	domainID := int64(decodeBody(t, rec)["id"].(float64))

	body := "Subject: hello\r\n\r\nthe body"
	if _, err := a.Server.blobs.Put("abc123", bytes.NewReader([]byte(body)), 0); err != nil {
		t.Fatal(err)
	}
	now := timeNow()
	if err := a.db.Enqueue(ctx, &store.Message{
		ID: "abc123", DomainID: domainID,
		EnvelopeFrom: "a@b.example", EnvelopeTo: []string{"c@example.com"},
		Subject: "hello", SizeBytes: int64(len(body)),
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	rec = a.do(t, "GET", "/api/v1/queue", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("queue listing returned %d", rec.Code)
	}
	if n := decodeBody(t, rec)["count"]; n != float64(1) {
		t.Fatalf("queue count = %v, want 1", n)
	}

	if bytes.Contains(rec.Body.Bytes(), []byte("the body")) {
		t.Error("SECURITY: the queue listing leaked the message body")
	}

	before, _ := a.db.ListEvents(ctx, 1000)
	rec = a.do(t, "GET", "/api/v1/queue/abc123/raw", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw returned %d", rec.Code)
	}
	if rec.Body.String() != body {
		t.Errorf("raw body = %q, want %q", rec.Body.String(), body)
	}

	after, _ := a.db.ListEvents(ctx, 1000)
	if len(after) <= len(before) {
		t.Fatal("SECURITY: reading a spooled message wrote no audit entry")
	}
	var found bool
	for _, e := range after {
		if e.Type == store.EventAdminRead {
			found = true
		}
	}
	if !found {
		t.Error("SECURITY: no admin_read_message event was recorded")
	}
}

func TestUnknownMessageIsNotFound(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	if rec := a.do(t, "GET", "/api/v1/queue/doesnotexist", nil, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	a := newTestAPI(t)
	rec := a.do(t, "GET", "/api/v1/setup", nil, nil)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("no Content-Security-Policy header")
	}
}

func timeNow() time.Time  { return time.Now().UTC() }
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestSMTPUserLifecycle(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)

	rec := a.do(t, "POST", "/api/v1/smtp-users", map[string]any{
		"username": "mailserver", "password": "a long submission password",
		"allowed_domains": []string{"example.com"},
	}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	id := int64(decodeBody(t, rec)["id"].(float64))

	rec = a.do(t, "POST", "/api/v1/smtp-users", map[string]any{
		"username": "mailserver", "password": "another long password here",
	}, cookie)
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate username returned %d, want 409", rec.Code)
	}

	if rec := a.do(t, "PATCH", "/api/v1/smtp-users/"+itoa(id),
		map[string]any{"enabled": false}, cookie); rec.Code != http.StatusOK {
		t.Errorf("disable returned %d", rec.Code)
	}
	if rec := a.do(t, "DELETE", "/api/v1/smtp-users/"+itoa(id), nil, cookie); rec.Code != http.StatusOK {
		t.Errorf("delete returned %d", rec.Code)
	}
}

func TestSMTPUserListingHidesTheHash(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	a.do(t, "POST", "/api/v1/smtp-users", map[string]any{
		"username": "mailserver", "password": "a long submission password",
	}, cookie)

	rec := a.do(t, "GET", "/api/v1/smtp-users", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("listing returned %d", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"argon2", "password_hash", "$argon2id$"} {
		if strings.Contains(body, leak) {
			t.Fatalf("SECURITY: the listing leaked %q:\n%s", leak, body)
		}
	}
}

func TestSMTPUserRejectsUnknownAllowedDomain(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/smtp-users", map[string]any{
		"username": "mailserver", "password": "a long submission password",
		"allowed_domains": []string{"not-configured.example"},
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("accepted an unknown allowed domain (status %d)", rec.Code)
	}
}

func TestSMTPUserRejectsWeakPassword(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/smtp-users", map[string]any{
		"username": "mailserver", "password": "short",
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("accepted a weak submission password (status %d)", rec.Code)
	}
}

func TestErrorCodes(t *testing.T) {
	a := newTestAPI(t)

	rec := a.do(t, "GET", "/api/v1/status", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["error"] != ErrAuthRequired {
		t.Fatalf("expected error %q, got %v", ErrAuthRequired, body["error"])
	}
	if _, exists := body["code"]; exists {
		t.Fatalf("expected response not to contain 'code' field")
	}

	cookie := a.setup(t)

	recSetupConflict := a.do(t, "POST", "/api/v1/setup", map[string]string{
		"email": "another@test.example", "password": testPassword,
	}, nil)
	if recSetupConflict.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", recSetupConflict.Code)
	}
	bodySetup := decodeBody(t, recSetupConflict)
	if bodySetup["error"] != ErrAlreadySetup {
		t.Fatalf("expected error %q, got %v", ErrAlreadySetup, bodySetup["error"])
	}

	recNotFound := a.do(t, "GET", "/api/v1/domains/99999", nil, cookie)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", recNotFound.Code)
	}
	bodyNotFound := decodeBody(t, recNotFound)
	if bodyNotFound["error"] != ErrDomainNotFound {
		t.Fatalf("expected error %q, got %v", ErrDomainNotFound, bodyNotFound["error"])
	}
}

func TestUserManagementAPI(t *testing.T) {
	a := newTestAPI(t)
	adminCookie := a.setup(t)

	rec := a.do(t, "GET", "/api/v1/users", nil, adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/users returned %d", rec.Code)
	}
	body := decodeBody(t, rec)
	usersList := body["users"].([]any)
	if len(usersList) != 1 {
		t.Fatalf("expected 1 user, got %d", len(usersList))
	}

	recCreate := a.do(t, "POST", "/api/v1/users", map[string]any{
		"email": "operator@test.example",
		"role":  "viewer",
	}, adminCookie)
	if recCreate.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/users returned %d", recCreate.Code)
	}
	created := decodeBody(t, recCreate)
	userID := int64(created["id"].(float64))
	if created["role"] != "viewer" {
		t.Fatalf("expected role viewer, got %v", created["role"])
	}

	recDup := a.do(t, "POST", "/api/v1/users", map[string]any{
		"email": "operator@test.example",
		"role":  "admin",
	}, adminCookie)
	if recDup.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate user, got %d", recDup.Code)
	}

	recUpdate := a.do(t, "PATCH", "/api/v1/users/"+itoa(userID), map[string]any{
		"role": "admin",
	}, adminCookie)
	if recUpdate.Code != http.StatusOK {
		t.Fatalf("PATCH /api/v1/users returned %d", recUpdate.Code)
	}

	hash, _ := auth.HashPassword(testPassword)
	_, _ = a.db.CreateUser(context.Background(), "viewer2@test.example", hash, store.RoleViewer)
	recLogin := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
		"email": "viewer2@test.example", "password": testPassword,
	}, nil)
	var viewerCookie *http.Cookie
	for _, c := range recLogin.Result().Cookies() {
		if c.Name == sessionCookie {
			viewerCookie = c
			break
		}
	}
	if viewerCookie == nil {
		t.Fatal("viewer login did not return session cookie")
	}

	recForbidden := a.do(t, "GET", "/api/v1/users", nil, viewerCookie)
	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer, got %d", recForbidden.Code)
	}

	recDelete := a.do(t, "DELETE", "/api/v1/users/"+itoa(userID), nil, adminCookie)
	if recDelete.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/users returned %d", recDelete.Code)
	}

	adminUser, _ := a.db.UserByEmail(context.Background(), "admin@test.example")
	recDeleteSelf := a.do(t, "DELETE", "/api/v1/users/"+itoa(adminUser.ID), nil, adminCookie)
	if recDeleteSelf.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when deleting self, got %d", recDeleteSelf.Code)
	}
}

func TestDMARCEndpoints(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie)
	domainID := int64(decodeBody(t, rec)["id"].(float64))

	recDmarc := a.do(t, "GET", "/api/v1/domains/"+itoa(domainID)+"/dmarc", nil, cookie)
	if recDmarc.Code != http.StatusOK {
		t.Fatalf("GET /dmarc returned %d", recDmarc.Code)
	}
	body := decodeBody(t, recDmarc)
	if body["domain"] != "example.com" {
		t.Errorf("expected domain example.com, got %v", body["domain"])
	}
	record, ok := body["record"].(map[string]any)
	if !ok || record["name"] != "_dmarc.example.com." {
		t.Errorf("invalid record format: %v", body["record"])
	}

	recCheck := a.do(t, "POST", "/api/v1/domains/"+itoa(domainID)+"/dmarc/check", nil, cookie)
	if recCheck.Code != http.StatusOK {
		t.Fatalf("POST /dmarc/check returned %d", recCheck.Code)
	}
}
