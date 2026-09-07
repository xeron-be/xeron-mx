package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func postYAML(t *testing.T, a *testAPI, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	req.RemoteAddr = "192.0.2.10:1234"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

func getRaw(t *testing.T, a *testAPI, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "192.0.2.10:1234"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

func TestConfigRoundTrip(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	imported := `
version: 1
domains:
  - name: example.test
    primary_host: mail.example.test
    primary_port: 2525
    primary_tls: starttls
    retention_hours: 48
    enabled: true
  - name: second.test
    primary_host: mail.second.test
smtp_users:
  - username: relaybot
    password: a long enough passphrase
    allowed_domains: [example.test]
`
	rec := postYAML(t, a, "/api/v1/config", imported, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("import returned %d: %s", rec.Code, rec.Body.String())
	}

	d, err := a.db.DomainByName(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("the domain was not created: %v", err)
	}
	if d.PrimaryHost != "mail.example.test" || d.PrimaryPort != 2525 ||
		d.PrimaryTLS != "starttls" || d.RetentionHours != 48 {
		t.Fatalf("imported domain is wrong: %+v", d)
	}
	if _, err := a.db.SMTPUserByName(context.Background(), "relaybot"); err != nil {
		t.Fatalf("the submission account was not created: %v", err)
	}

	rec = getRaw(t, a, "/api/v1/config", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("export returned %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("export Content-Type = %q", ct)
	}

	var doc configDocument
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the export is not valid YAML: %v", err)
	}
	if len(doc.Domains) != 2 || len(doc.SMTPUsers) != 1 {
		t.Fatalf("export has %d domains and %d accounts", len(doc.Domains), len(doc.SMTPUsers))
	}

	rec = postYAML(t, a, "/api/v1/config", rec.Body.String(), cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-import returned %d: %s", rec.Code, rec.Body.String())
	}
	var report map[string]any
	json.Unmarshal(rec.Body.Bytes(), &report)
	for _, entry := range report["domains"].([]any) {
		if action := entry.(map[string]any)["action"]; action != "unchanged" {
			t.Errorf("re-importing an export reports %v, want unchanged", action)
		}
	}
}

func TestExportCarriesNoSecret(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	postYAML(t, a, "/api/v1/config", `
domains:
  - name: example.test
    primary_host: mail.example.test
smtp_users:
  - username: relaybot
    password: a long enough passphrase
`, cookie)

	rec := getRaw(t, a, "/api/v1/config", cookie)
	body := rec.Body.String()
	for _, secret := range []string{"a long enough passphrase", "password_hash", "$argon2"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(secret)) {
			t.Fatalf("SECURITY: the export contains %q", secret)
		}
	}

	var doc configDocument
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.SMTPUsers) == 0 {
		t.Fatal("the account is missing from the export")
	}
	for _, u := range doc.SMTPUsers {
		if u.Password != "" {
			t.Fatalf("SECURITY: %s was exported with a password field", u.Username)
		}
	}
}

func TestImportIsAtomicOnValidationFailure(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := postYAML(t, a, "/api/v1/config", `
domains:
  - name: good.test
    primary_host: mail.good.test
  - name: broken.test
    primary_host: mail.broken.test
    primary_tls: nonsense
`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if _, err := a.db.DomainByName(context.Background(), "good.test"); err == nil {
		t.Fatal("the valid half of a rejected document was applied; the import is not atomic")
	}
}

func TestImportDryRunChangesNothing(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := postYAML(t, a, "/api/v1/config?dry_run=true", `
domains:
  - name: example.test
    primary_host: mail.example.test
`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run returned %d: %s", rec.Code, rec.Body.String())
	}

	var report map[string]any
	json.Unmarshal(rec.Body.Bytes(), &report)
	if report["dry_run"] != true {
		t.Error("the report does not say it was a dry run")
	}
	if _, err := a.db.DomainByName(context.Background(), "example.test"); err == nil {
		t.Fatal("a dry run created the domain")
	}
}

func TestImportNeverDeletes(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	postYAML(t, a, "/api/v1/config", "domains:\n  - name: keep.test\n    primary_host: mail.keep.test\n", cookie)
	postYAML(t, a, "/api/v1/config", "domains:\n  - name: other.test\n    primary_host: mail.other.test\n", cookie)

	if _, err := a.db.DomainByName(context.Background(), "keep.test"); err != nil {
		t.Fatal("a domain absent from the document was deleted; queued mail would have gone with it")
	}
}

func TestImportUpdatesAnExistingDomain(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	postYAML(t, a, "/api/v1/config", "domains:\n  - name: example.test\n    primary_host: old.example.test\n", cookie)
	rec := postYAML(t, a, "/api/v1/config",
		"domains:\n  - name: example.test\n    primary_host: new.example.test\n    retention_hours: 12\n", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("import returned %d: %s", rec.Code, rec.Body.String())
	}

	d, err := a.db.DomainByName(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if d.PrimaryHost != "new.example.test" || d.RetentionHours != 12 {
		t.Fatalf("the domain was not updated: %+v", d)
	}
}

func TestImportRejectsUnknownFields(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := postYAML(t, a, "/api/v1/config",
		"domains:\n  - name: example.test\n    primary_host: mail.example.test\n    retenion_hours: 12\n", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a typo in a field name returned %d, want 400", rec.Code)
	}
}

func TestImportRejectsAnAllowedDomainThatDoesNotExist(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := postYAML(t, a, "/api/v1/config", `
smtp_users:
  - username: relaybot
    password: a long enough passphrase
    allowed_domains: [nowhere.test]
`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestImportAllowsADomainDefinedInTheSameDocument(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := postYAML(t, a, "/api/v1/config", `
domains:
  - name: example.test
    primary_host: mail.example.test
smtp_users:
  - username: relaybot
    password: a long enough passphrase
    allowed_domains: [example.test]
`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestImportSkipsANewAccountWithNoPassword(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := postYAML(t, a, "/api/v1/config", "smtp_users:\n  - username: relaybot\n", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("returned %d: %s", rec.Code, rec.Body.String())
	}
	var report map[string]any
	json.Unmarshal(rec.Body.Bytes(), &report)
	if len(report["warnings"].([]any)) == 0 {
		t.Error("no warning was reported for an account that could not be created")
	}
	if _, err := a.db.SMTPUserByName(context.Background(), "relaybot"); err == nil {
		t.Fatal("an account was created with no password")
	}
}

func TestConfigEndpointsAreAdminOnly(t *testing.T) {
	a := newTestAPI(t)

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/config"},
		{"POST", "/api/v1/config"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
		req.RemoteAddr = "192.0.2.10:1234"
		rec := httptest.NewRecorder()
		a.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("SECURITY: %s %s returned %d to an anonymous caller, want 401",
				tc.method, tc.path, rec.Code)
		}
	}
}
