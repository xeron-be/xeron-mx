package api

import (
	"fmt"
	"net/http"
	"testing"
)

func TestADomainCarriesItsMonthlySendingLimit(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "hosted.example", "primary_host": "mail.example.net", "monthly_send_limit": 500,
	}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	created := decodeBody(t, rec)
	if created["monthly_send_limit"] != float64(500) || created["sent_this_month"] != float64(0) {
		t.Fatalf("created domain = %v; want a limit of 500 and nothing sent", created)
	}
	path := fmt.Sprintf("/api/v1/domains/%v", created["id"])

	rec = a.do(t, "PATCH", path, map[string]any{"primary_port": 587}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d: %s", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, a.do(t, "GET", path, nil, cookie))["monthly_send_limit"]; got != float64(500) {
		t.Fatalf("an unrelated change dropped the limit: %v", got)
	}

	rec = a.do(t, "PATCH", path, map[string]any{"monthly_send_limit": 0}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch returned %d: %s", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, a.do(t, "GET", path, nil, cookie))["monthly_send_limit"]; got != nil {
		t.Fatalf("a limit of 0 left %v; want no limit", got)
	}
}
