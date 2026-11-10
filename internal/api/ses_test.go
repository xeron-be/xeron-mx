package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/xeron-be/xeron-mx/internal/ses"
	"github.com/xeron-be/xeron-mx/internal/ses/sestest"
)

func (a *testAPI) withSES(t *testing.T) *sestest.Fake {
	t.Helper()
	fake := sestest.New()
	a.SetSES(ses.NewManager(fake, a.db, slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
		"eu-west-3", 0, "mx2.test.example"))
	return fake
}

func (a *testAPI) addSESDomain(t *testing.T, cookie *http.Cookie, name string) string {
	t.Helper()
	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": name, "primary_host": "mail.example.net",
	}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	return fmt.Sprintf("/api/v1/domains/%v", decodeBody(t, rec)["id"])
}

func TestSESIsReportedOffWhenNotConfigured(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	if got := decodeBody(t, a.do(t, "GET", "/api/v1/ses", nil, cookie)); got["enabled"] != false {
		t.Fatalf("status = %v", got)
	}
	path := a.addSESDomain(t, cookie, "client.example")
	if got := decodeBody(t, a.do(t, "GET", path, nil, cookie)); got["ses_status"] != nil {
		t.Fatalf("a domain carries an SES status with SES off: %v", got)
	}
	if rec := a.do(t, "POST", path+"/ses/check", nil, cookie); rec.Code != http.StatusConflict {
		t.Fatalf("check with SES off returned %d", rec.Code)
	}
	if rec := a.do(t, "DELETE", path+"?ses_identity=delete", nil, cookie); rec.Code != http.StatusConflict {
		t.Fatalf("deleting an identity with SES off returned %d", rec.Code)
	}
}

func TestSESRecordsAndStatusAreExposed(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	fake := a.withSES(t)
	path := a.addSESDomain(t, cookie, "client.example")

	got := decodeBody(t, a.do(t, "GET", path+"/ses", nil, cookie))
	if got["status"] != sesUnknown {
		t.Fatalf("before any pass: %v", got)
	}

	rec := a.do(t, "POST", path+"/ses/check", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("check returned %d: %s", rec.Code, rec.Body.String())
	}
	got = decodeBody(t, rec)
	if got["status"] != "pending" || got["identity"] != "client.example" || got["managed"] != true || got["deletable"] != true {
		t.Fatalf("after check: %v", got)
	}
	records, _ := got["records"].([]any)
	if len(records) != 3 {
		t.Fatalf("records = %v", got["records"])
	}
	first, _ := records[0].(map[string]any)
	if first["type"] != "CNAME" || first["value"] != "clientexamplea1.dkim.amazonses.com" ||
		first["name"] != "clientexamplea1._domainkey.client.example" {
		t.Fatalf("record = %v", first)
	}

	fake.SetStatus("client.example", ses.StatusSuccess)
	a.do(t, "POST", path+"/ses/check", nil, cookie)
	if got := decodeBody(t, a.do(t, "GET", path, nil, cookie)); got["ses_status"] != "verified" {
		t.Fatalf("domain = %v", got)
	}

	status := decodeBody(t, a.do(t, "GET", "/api/v1/ses", nil, cookie))
	if status["enabled"] != true || status["region"] != "eu-west-3" {
		t.Fatalf("ses status = %v", status)
	}
}

func TestDeletingADomainKeepsItsSESIdentityUnlessAsked(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	fake := a.withSES(t)

	kept := a.addSESDomain(t, cookie, "kept.example")
	gone := a.addSESDomain(t, cookie, "gone.example")
	a.do(t, "POST", kept+"/ses/check", nil, cookie)
	a.do(t, "POST", gone+"/ses/check", nil, cookie)

	if rec := a.do(t, "DELETE", kept, nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("delete returned %d", rec.Code)
	}
	if !fake.Has("kept.example") {
		t.Fatal("the SES identity was deleted without being asked")
	}

	rec := a.do(t, "DELETE", gone+"?ses_identity=delete", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", rec.Code, rec.Body.String())
	}
	if fake.Has("gone.example") || decodeBody(t, rec)["ses_identity_deleted"] != true {
		t.Fatal("the SES identity survived an explicit delete")
	}
}

func TestAnInheritedOrAdoptedIdentityIsNeverDeleted(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	fake := a.withSES(t)
	fake.Put("xeron.example", ses.StatusSuccess)

	parent := a.addSESDomain(t, cookie, "xeron.example")
	child := a.addSESDomain(t, cookie, "client.xeron.example")
	if err := a.ses.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := decodeBody(t, a.do(t, "GET", child+"/ses", nil, cookie))
	if got["inherited"] != true || got["identity"] != "xeron.example" || got["deletable"] != false {
		t.Fatalf("child = %v", got)
	}
	for _, path := range []string{child, parent} {
		rec := a.do(t, "DELETE", path+"?ses_identity=delete", nil, cookie)
		if rec.Code != http.StatusConflict || decodeBody(t, rec)["error"] != ErrSESIdentityNotManaged {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if !fake.Has("xeron.example") {
		t.Fatal("an identity created by hand was deleted")
	}
	if rec := a.do(t, "GET", child, nil, cookie); rec.Code != http.StatusOK {
		t.Fatal("a refused identity deletion still removed the domain")
	}
}
