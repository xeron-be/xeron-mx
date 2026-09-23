package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func (a *testAPI) addDomain(t *testing.T, cookie *http.Cookie, name string) string {
	t.Helper()
	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{"name": name, "primary_host": "mail." + name}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create domain: %d %s", rec.Code, rec.Body.String())
	}
	return itoa(int64(decodeBody(t, rec)["id"].(float64)))
}

func recipientsOf(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["recipients"].([]any)
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i], _ = v.(string)
	}
	return out
}

func TestKnownRecipientsCanBeSetAndRead(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	id := a.addDomain(t, cookie, "example.test")
	path := "/api/v1/domains/" + id + "/recipients"

	if got := recipientsOf(t, decodeBody(t, a.do(t, "GET", path, nil, cookie))); len(got) != 0 {
		t.Fatalf("a new domain has recipients %v", got)
	}

	rec := a.do(t, "PUT", path, map[string]any{
		"recipients": []string{"Bob@Example.test", "alice@example.test", "", "alice@example.test"},
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT recipients: %d %s", rec.Code, rec.Body.String())
	}
	if got := strings.Join(recipientsOf(t, decodeBody(t, rec)), ","); got != "alice@example.test,bob@example.test" {
		t.Fatalf("stored %q; want the list cleaned, sorted and deduplicated", got)
	}

	domain := decodeBody(t, a.do(t, "GET", "/api/v1/domains/"+id, nil, cookie))
	if n, _ := domain["recipients_count"].(float64); n != 2 {
		t.Fatalf("recipients_count = %v; want 2", domain["recipients_count"])
	}

	events, err := a.db.ListEvents(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	audited := false
	for _, e := range events {
		audited = audited || e.Type == "recipients_updated"
	}
	if !audited {
		t.Fatal("changing who may receive mail left no trace on the timeline")
	}
}

func TestKnownRecipientsMustBelongToTheDomain(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	id := a.addDomain(t, cookie, "example.test")

	for _, bad := range []string{"bob@other.test", "no-at-sign", "@example.test", "bob smith@example.test", "a@example.test,b@example.test"} {
		rec := a.do(t, "PUT", "/api/v1/domains/"+id+"/recipients", map[string]any{"recipients": []string{bad}}, cookie)
		if rec.Code != http.StatusBadRequest || decodeBody(t, rec)["error"] != ErrInvalidRecipient {
			t.Fatalf("%q: %d %s; want 400 invalid_recipient", bad, rec.Code, rec.Body.String())
		}
	}
}

func TestOnlyAnAdminSetsKnownRecipients(t *testing.T) {
	a := newTestAPI(t)
	admin := a.setup(t)
	id := a.addDomain(t, admin, "example.test")

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := a.db.CreateUser(context.Background(), "op@test.example", hash, store.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	token, tokenHash, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.db.CreateSession(context.Background(), tokenHash, opID, config.Default().HTTP.SessionTTL, "test"); err != nil {
		t.Fatal(err)
	}
	operator := &http.Cookie{Name: sessionCookie, Value: token}

	if rec := a.do(t, "GET", "/api/v1/domains/"+id+"/recipients", nil, operator); rec.Code != http.StatusOK {
		t.Fatalf("an operator cannot read the list: %d", rec.Code)
	}
	rec := a.do(t, "PUT", "/api/v1/domains/"+id+"/recipients", map[string]any{"recipients": []string{"a@example.test"}}, operator)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: an operator changed who may receive mail (status %d)", rec.Code)
	}
	if rec := a.do(t, "PUT", "/api/v1/domains/"+id+"/recipients", map[string]any{"recipients": []string{"a@example.test"}}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: anonymous PUT returned %d", rec.Code)
	}
}

func TestKnownRecipientsTravelThroughTheConfigDocument(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	doc := `
version: 1
domains:
  - name: listed.test
    primary_host: mail.listed.test
    recipients: [alice@listed.test, Bob@Listed.test]
  - name: open.test
    primary_host: mail.open.test
`
	if rec := postYAML(t, a, "/api/v1/config", doc, cookie); rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	exported := getRaw(t, a, "/api/v1/config", cookie).Body.String()
	if !strings.Contains(exported, "- alice@listed.test\n") || !strings.Contains(exported, "- bob@listed.test\n") {
		t.Fatalf("the export lost the list:\n%s", exported)
	}
	if strings.Count(exported, "recipients:") != 1 {
		t.Fatalf("a domain without a list exported one:\n%s", exported)
	}

	again := decodeBody(t, postYAML(t, a, "/api/v1/config?dry_run=true", exported, cookie))
	if n, _ := again["changed"].(float64); n != 0 {
		t.Fatalf("re-importing the export would change %v things; want 0", again["changed"])
	}

	untouched := decodeBody(t, postYAML(t, a, "/api/v1/config?dry_run=true", `
version: 1
domains:
  - name: listed.test
    primary_host: mail.listed.test
`, cookie))
	if n, _ := untouched["changed"].(float64); n != 0 {
		t.Fatal("a document without the key would clear the list; leaving it out must leave it alone")
	}

	rec := postYAML(t, a, "/api/v1/config", `
version: 1
domains:
  - name: listed.test
    primary_host: mail.listed.test
    recipients: []
`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("clearing import: %d %s", rec.Code, rec.Body.String())
	}
	d, err := a.db.DomainByName(context.Background(), "listed.test")
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := a.db.DomainRecipients(context.Background(), d.ID); len(list) != 0 {
		t.Fatalf("an explicit empty list left %v", list)
	}

	bad := postYAML(t, a, "/api/v1/config", `
version: 1
domains:
  - name: listed.test
    primary_host: mail.listed.test
    recipients: [someone@elsewhere.test]
`, cookie)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("a recipient outside the domain was imported: %d", bad.Code)
	}
}

func TestAMessageShowsItsMalwareScanOutcome(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "scan.example", "primary_host": "mail.scan.example",
	}, cookie)
	domainID := int64(decodeBody(t, rec)["id"].(float64))

	now := time.Now().UTC()
	if err := a.db.Enqueue(context.Background(), &store.Message{
		ID: "scanned", DomainID: domainID, EnvelopeFrom: "a@b.test",
		EnvelopeTo: []string{"c@scan.example"}, SizeBytes: 1, ReceivedAt: now,
		ExpiresAt: now.Add(time.Hour), NextRetryAt: now,
		MalwareScan: "skipped: larger than 26214400 bytes",
	}); err != nil {
		t.Fatal(err)
	}
	rec = a.do(t, "GET", "/api/v1/queue/scanned", nil, cookie)
	if rec.Code != 200 {
		t.Fatalf("GET returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	m, _ := body["message"].(map[string]any)
	if m == nil {
		m = body
	}
	if m["malware_scan"] != "skipped: larger than 26214400 bytes" {
		t.Fatalf("malware_scan = %v", m["malware_scan"])
	}
}
