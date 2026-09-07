package api

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func TestOperatorAndDomainScoping(t *testing.T) {
	a := newTestAPI(t)
	adminCookie := a.setup(t)

	d1Rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "alpha.example", "primary_host": "mail.alpha.example", "primary_port": 25,
	}, adminCookie)
	if d1Rec.Code != http.StatusCreated {
		t.Fatalf("create domain alpha returned %d: %s", d1Rec.Code, d1Rec.Body.String())
	}
	d1ID := int64(decodeBody(t, d1Rec)["id"].(float64))

	d2Rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "beta.example", "primary_host": "mail.beta.example", "primary_port": 25,
	}, adminCookie)
	if d2Rec.Code != http.StatusCreated {
		t.Fatalf("create domain beta returned %d: %s", d2Rec.Code, d2Rec.Body.String())
	}
	d2ID := int64(decodeBody(t, d2Rec)["id"].(float64))

	ctx := context.Background()
	m1ID := "msg-alpha-1"
	err := a.db.Enqueue(ctx, &store.Message{
		ID:           m1ID,
		DomainID:     d1ID,
		EnvelopeFrom: "sender@test.com",
		EnvelopeTo:   []string{"dest@alpha.example"},
		Subject:      "Alpha test",
		SizeBytes:    100,
		ReceivedAt:   time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		Status:       store.StatusQueued,
	})
	if err != nil {
		t.Fatalf("enqueue msg 1: %v", err)
	}

	m2ID := "msg-beta-1"
	err = a.db.Enqueue(ctx, &store.Message{
		ID:           m2ID,
		DomainID:     d2ID,
		EnvelopeFrom: "sender@test.com",
		EnvelopeTo:   []string{"dest@beta.example"},
		Subject:      "Beta test",
		SizeBytes:    200,
		ReceivedAt:   time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		Status:       store.StatusQueued,
	})
	if err != nil {
		t.Fatalf("enqueue msg 2: %v", err)
	}

	uRec := a.do(t, "POST", "/api/v1/users", map[string]any{
		"email":           "operator@alpha.example",
		"role":            store.RoleOperator,
		"password":        "validPassword123!",
		"allowed_domains": []string{"alpha.example"},
	}, adminCookie)
	if uRec.Code != http.StatusCreated {
		t.Fatalf("create operator user returned %d: %s", uRec.Code, uRec.Body.String())
	}
	uBody := decodeBody(t, uRec)
	if uBody["role"] != store.RoleOperator {
		t.Fatalf("role = %v, want operator", uBody["role"])
	}

	loginRec := a.do(t, "POST", "/api/v1/auth/login", map[string]any{
		"email":    "operator@alpha.example",
		"password": "validPassword123!",
	}, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("operator login returned %d: %s", loginRec.Code, loginRec.Body.String())
	}
	opCookie := loginRec.Result().Cookies()[0]

	meRec := a.do(t, "GET", "/api/v1/auth/me", nil, opCookie)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me returned %d: %s", meRec.Code, meRec.Body.String())
	}
	meBody := decodeBody(t, meRec)
	if meBody["role"] != store.RoleOperator {
		t.Errorf("me role = %v, want operator", meBody["role"])
	}
	allowedList, ok := meBody["allowed_domains"].([]any)
	if !ok || len(allowedList) != 1 || allowedList[0] != "alpha.example" {
		t.Errorf("me allowed_domains = %v, want [alpha.example]", meBody["allowed_domains"])
	}

	domsRec := a.do(t, "GET", "/api/v1/domains", nil, opCookie)
	if domsRec.Code != http.StatusOK {
		t.Fatalf("domains list returned %d: %s", domsRec.Code, domsRec.Body.String())
	}
	domsList := decodeBody(t, domsRec)["domains"].([]any)
	if len(domsList) != 1 {
		t.Fatalf("operator saw %d domains, want 1", len(domsList))
	}
	if domsList[0].(map[string]any)["name"] != "alpha.example" {
		t.Errorf("operator domain = %v, want alpha.example", domsList[0].(map[string]any)["name"])
	}

	d2GetRec := a.do(t, "GET", "/api/v1/domains/"+strconv.FormatInt(d2ID, 10), nil, opCookie)
	if d2GetRec.Code != http.StatusNotFound {
		t.Errorf("accessing unauthorized domain returned %d, want 404", d2GetRec.Code)
	}

	qRec := a.do(t, "GET", "/api/v1/queue", nil, opCookie)
	if qRec.Code != http.StatusOK {
		t.Fatalf("queue returned %d: %s", qRec.Code, qRec.Body.String())
	}
	msgs := decodeBody(t, qRec)["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("operator saw %d messages, want 1", len(msgs))
	}
	if msgs[0].(map[string]any)["id"] != m1ID {
		t.Errorf("operator saw message %v, want %s", msgs[0].(map[string]any)["id"], m1ID)
	}

	m2GetRec := a.do(t, "GET", "/api/v1/queue/"+m2ID, nil, opCookie)
	if m2GetRec.Code != http.StatusNotFound {
		t.Errorf("accessing unauthorized message returned %d, want 404", m2GetRec.Code)
	}

	retryM2Rec := a.do(t, "POST", "/api/v1/queue/"+m2ID+"/retry", nil, opCookie)
	if retryM2Rec.Code != http.StatusNotFound {
		t.Errorf("retrying unauthorized message returned %d, want 404", retryM2Rec.Code)
	}

	retryM1Rec := a.do(t, "POST", "/api/v1/queue/"+m1ID+"/retry", nil, opCookie)
	if retryM1Rec.Code != http.StatusOK {
		t.Errorf("retrying authorized message returned %d, want 200", retryM1Rec.Code)
	}

	usersRec := a.do(t, "GET", "/api/v1/users", nil, opCookie)
	if usersRec.Code != http.StatusForbidden {
		t.Errorf("operator accessing /users returned %d, want 403", usersRec.Code)
	}

	tokensRec := a.do(t, "GET", "/api/v1/tokens", nil, opCookie)
	if tokensRec.Code != http.StatusForbidden {
		t.Errorf("operator accessing /tokens returned %d, want 403", tokensRec.Code)
	}

	statRec := a.do(t, "GET", "/api/v1/status", nil, opCookie)
	if statRec.Code != http.StatusOK {
		t.Fatalf("status returned %d: %s", statRec.Code, statRec.Body.String())
	}
	statBody := decodeBody(t, statRec)
	statDoms := statBody["domains"].([]any)
	if len(statDoms) != 1 {
		t.Errorf("status domains length = %d, want 1", len(statDoms))
	}
	queueStats := statBody["queue"].(map[string]any)
	if queueStats["pending"].(float64) != 1 {
		t.Errorf("operator pending = %v, want 1", queueStats["pending"])
	}
}

func TestUpdateUserScopeAndPermissions(t *testing.T) {
	a := newTestAPI(t)
	adminCookie := a.setup(t)

	uRec := a.do(t, "POST", "/api/v1/users", map[string]any{
		"email":           "viewer@test.example",
		"role":            store.RoleViewer,
		"password":        "validPassword123!",
		"allowed_domains": []string{"alpha.example"},
	}, adminCookie)
	if uRec.Code != http.StatusCreated {
		t.Fatalf("create viewer: %s", uRec.Body.String())
	}
	uID := int64(decodeBody(t, uRec)["id"].(float64))

	patchRec := a.do(t, "PATCH", "/api/v1/users/"+strconv.FormatInt(uID, 10), map[string]any{
		"role":            store.RoleOperator,
		"allowed_domains": []string{"alpha.example", "beta.example"},
	}, adminCookie)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch user: %s", patchRec.Body.String())
	}
	patchBody := decodeBody(t, patchRec)
	if patchBody["role"] != store.RoleOperator {
		t.Fatalf("role after patch = %v, want operator", patchBody["role"])
	}
	allowed := patchBody["allowed_domains"].([]any)
	if len(allowed) != 2 {
		t.Fatalf("allowed_domains count = %d, want 2", len(allowed))
	}

	adminMeRec := a.do(t, "GET", "/api/v1/auth/me", nil, adminCookie)
	adminID := int64(decodeBody(t, adminMeRec)["id"].(float64))
	demoteAdminRec := a.do(t, "PATCH", "/api/v1/users/"+strconv.FormatInt(adminID, 10), map[string]any{
		"role": store.RoleViewer,
	}, adminCookie)
	if demoteAdminRec.Code != http.StatusBadRequest {
		t.Errorf("demoting last admin returned %d, want 400", demoteAdminRec.Code)
	}
}

func TestMaintenanceDrainAndDiskGuardAPI(t *testing.T) {
	a := newTestAPI(t)
	adminCookie := a.setup(t)

	m := maintenance.NewManager(false)
	a.SetMaintenance(m)
	a.SetDiskGuard("/spool", 1000, func(path string) (uint64, error) {
		return 5000, nil
	})

	rec := a.do(t, "GET", "/api/v1/maintenance/drain", nil, adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /maintenance/drain returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["draining"] != false {
		t.Fatalf("expected draining false, got %v", body["draining"])
	}

	statusRec := a.do(t, "GET", "/api/v1/status", nil, adminCookie)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("GET /status returned %d: %s", statusRec.Code, statusRec.Body.String())
	}
	statusBody := decodeBody(t, statusRec)
	if statusBody["draining"] != false {
		t.Fatalf("expected status draining false, got %v", statusBody["draining"])
	}
	diskInfo, ok := statusBody["disk"].(map[string]any)
	if !ok {
		t.Fatalf("expected disk info in status, got %v", statusBody["disk"])
	}
	if diskInfo["guard_enabled"] != true || diskInfo["available_bytes"].(float64) != 5000 {
		t.Fatalf("unexpected disk info: %v", diskInfo)
	}

	enableRec := a.do(t, "POST", "/api/v1/maintenance/drain", map[string]any{"enabled": true}, adminCookie)
	if enableRec.Code != http.StatusOK {
		t.Fatalf("POST /maintenance/drain returned %d: %s", enableRec.Code, enableRec.Body.String())
	}
	if decodeBody(t, enableRec)["draining"] != true {
		t.Fatal("expected draining true after enable")
	}
	if !m.IsDraining() {
		t.Fatal("expected manager to be draining")
	}

	disableRec := a.do(t, "POST", "/api/v1/maintenance/drain", map[string]any{"enabled": false}, adminCookie)
	if disableRec.Code != http.StatusOK {
		t.Fatalf("POST /maintenance/drain disable returned %d", disableRec.Code)
	}
	if decodeBody(t, disableRec)["draining"] != false {
		t.Fatal("expected draining false after disable")
	}
	if m.IsDraining() {
		t.Fatal("expected manager not to be draining")
	}
}
