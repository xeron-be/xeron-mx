package api

import (
	"net/http"
	"testing"

	"github.com/xeron-be/xeron-mx/internal/store"
)

func timelineOf(t *testing.T, a *testAPI, cookie *http.Cookie) []map[string]any {
	t.Helper()
	rec := a.do(t, "GET", "/api/v1/events?limit=100", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("events returned %d: %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	for _, e := range decodeBody(t, rec)["events"].([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func eventOfType(t *testing.T, events []map[string]any, typ string) (map[string]any, map[string]any) {
	t.Helper()
	for _, e := range events {
		if e["type"] == typ {
			data, _ := e["data"].(map[string]any)
			return e, data
		}
	}
	t.Fatalf("no %s event in the timeline", typ)
	return nil, nil
}

func TestTheTimelineSaysWhoDidWhatAndFromWhere(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "billing", store.RoleAdmin)

	if rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.com", "primary_host": "mail.example.com",
	}, cookie); rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	if rec := a.doAuth(t, "POST", "/api/v1/domains", token, map[string]any{
		"name": "example.org", "primary_host": "mail.example.org",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create through the token returned %d: %s", rec.Code, rec.Body.String())
	}
	if c, _, _ := sessionFrom(t, a, "nobody@test.example", testPassword, ""); c != nil {
		t.Fatal("an unknown account logged in")
	}
	if c, _, _ := sessionFrom(t, a, "admin@test.example", "not the password", ""); c != nil {
		t.Fatal("a wrong password logged in")
	}

	events := timelineOf(t, a, cookie)

	var bySession, byToken map[string]any
	for _, e := range events {
		if e["type"] != store.EventDomainAdded {
			continue
		}
		data := e["data"].(map[string]any)
		switch data["name"] {
		case "example.com":
			bySession = e
		case "example.org":
			byToken = e
		}
	}
	if bySession == nil || byToken == nil {
		t.Fatalf("domain_added events missing: %v", events)
	}
	for name, e := range map[string]map[string]any{"session": bySession, "token": byToken} {
		data := e["data"].(map[string]any)
		if e["user"] != "admin@test.example" || data["by"] != "admin@test.example" {
			t.Errorf("%s: the event does not name the account: user=%v by=%v", name, e["user"], data["by"])
		}
		if data["ip"] == nil || data["ip"] == "" {
			t.Errorf("%s: the event has no address", name)
		}
		if e["domain_name"] == nil {
			t.Errorf("%s: the event does not name the domain", name)
		}
	}
	if byToken["data"].(map[string]any)["via_token"] != "billing" {
		t.Errorf("the token is not named: %v", byToken["data"])
	}
	if _, set := bySession["data"].(map[string]any)["via_token"]; set {
		t.Errorf("a session action claims a token: %v", bySession["data"])
	}

	reasons := map[string]bool{}
	for _, e := range events {
		if e["type"] == store.EventLoginFailed {
			reasons[e["data"].(map[string]any)["reason"].(string)] = true
		}
	}
	if !reasons["unknown_account"] || !reasons["wrong_password"] {
		t.Errorf("failed logins do not say why: %v", reasons)
	}

	_, login := eventOfType(t, events, store.EventLogin)
	if login["by"] != "admin@test.example" {
		t.Errorf("the login does not name the account: %v", login)
	}
}
