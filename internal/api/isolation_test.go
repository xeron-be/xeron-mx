package api

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type tenants struct {
	admin, scoped, unscoped *http.Cookie
	alphaID, betaID         int64
}

func (a *testAPI) login(t *testing.T, email string) *http.Cookie {
	t.Helper()
	rec := a.do(t, "POST", "/api/v1/auth/login", map[string]any{"email": email, "password": testPassword}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s returned %d: %s", email, rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatalf("login %s returned no session cookie", email)
	return nil
}

func twoTenants(t *testing.T, a *testAPI) tenants {
	t.Helper()
	var tn tenants
	tn.admin = a.setup(t)
	for _, name := range []string{"alpha.example", "beta.example"} {
		rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
			"name": name, "primary_host": "mail." + name,
		}, tn.admin)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s returned %d: %s", name, rec.Code, rec.Body.String())
		}
		id := int64(decodeBody(t, rec)["id"].(float64))
		if name == "alpha.example" {
			tn.alphaID = id
		} else {
			tn.betaID = id
		}
	}
	for email, domains := range map[string][]string{
		"customer@alpha.example": {"alpha.example"},
		"ops@test.example":       nil,
	} {
		rec := a.do(t, "POST", "/api/v1/users", map[string]any{
			"email": email, "role": store.RoleOperator, "password": testPassword,
			"allowed_domains": domains,
		}, tn.admin)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s returned %d: %s", email, rec.Code, rec.Body.String())
		}
	}
	tn.scoped = a.login(t, "customer@alpha.example")
	tn.unscoped = a.login(t, "ops@test.example")
	return tn
}

func TestFleetWideListingsAreClosedToDomainScopedUsers(t *testing.T) {
	a := newTestAPI(t)
	tn := twoTenants(t, a)

	for _, path := range []string{
		"/api/v1/smtp-users",
		"/api/v1/routes",
		"/api/v1/routes/test?destination=beta.example",
		"/api/v1/filters",
		"/api/v1/webhooks",
		"/api/v1/webhooks/deliveries",
		"/api/v1/cluster",
	} {
		rec := a.do(t, "GET", path, nil, tn.scoped)
		if rec.Code != http.StatusForbidden || decodeBody(t, rec)["error"] != ErrDomainScoped {
			t.Errorf("SECURITY: GET %s as a user scoped to alpha.example returned %d %s; want 403 %s",
				path, rec.Code, rec.Body.String(), ErrDomainScoped)
		}
		for who, cookie := range map[string]*http.Cookie{"admin": tn.admin, "unscoped operator": tn.unscoped} {
			if rec := a.do(t, "GET", path, nil, cookie); rec.Code == http.StatusForbidden {
				t.Errorf("GET %s as %s returned 403; only domain-scoped users are refused", path, who)
			}
		}
	}
}

func TestOnlyAnAdminCanDrainTheNode(t *testing.T) {
	a := newTestAPI(t)
	tn := twoTenants(t, a)
	m := maintenance.NewManager(false)
	a.SetMaintenance(m)

	for who, cookie := range map[string]*http.Cookie{"scoped operator": tn.scoped, "unscoped operator": tn.unscoped} {
		rec := a.do(t, "POST", "/api/v1/maintenance/drain", map[string]any{"enabled": true}, cookie)
		if rec.Code != http.StatusForbidden {
			t.Errorf("SECURITY: POST /maintenance/drain as %s returned %d; draining refuses mail for every domain on the node", who, rec.Code)
		}
		if m.IsDraining() {
			t.Fatalf("SECURITY: the %s drained the node", who)
		}
		if rec := a.do(t, "GET", "/api/v1/maintenance/drain", nil, cookie); rec.Code != http.StatusOK {
			t.Errorf("GET /maintenance/drain as %s returned %d; reading the state stays open to operators", who, rec.Code)
		}
	}
	if rec := a.do(t, "POST", "/api/v1/maintenance/drain", map[string]any{"enabled": true}, tn.admin); rec.Code != http.StatusOK {
		t.Fatalf("POST /maintenance/drain as admin returned %d: %s", rec.Code, rec.Body.String())
	}
	if !m.IsDraining() {
		t.Fatal("the admin's drain did not take effect")
	}
}

func openLive(t *testing.T, a *testAPI, srv *httptest.Server, cookie *http.Cookie) <-chan string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/live", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	before := a.hub.clientCount()
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /live returned %d", resp.StatusCode)
	}

	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				lines <- data
			}
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for a.hub.clientCount() <= before {
		if time.Now().After(deadline) {
			t.Fatal("the live stream never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return lines
}

func collectUntil(t *testing.T, lines <-chan string, marker string) []string {
	t.Helper()
	var got []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the live stream closed before %q arrived; got %q", marker, got)
			}
			got = append(got, line)
			if strings.Contains(line, marker) {
				return got
			}
		case <-timeout:
			t.Fatalf("%q never arrived; got %q", marker, got)
		}
	}
}

func TestLiveStreamOnlyCarriesTheUsersOwnDomains(t *testing.T) {
	a := newTestAPI(t)
	tn := twoTenants(t, a)
	ctx := context.Background()
	for id, domainID := range map[string]int64{"msg-alpha": tn.alphaID, "msg-beta": tn.betaID} {
		if err := a.db.Enqueue(ctx, &store.Message{
			ID: id, DomainID: domainID, EnvelopeFrom: "sender@test.example", EnvelopeTo: []string{"rcpt@test.example"},
			SizeBytes: 10, ReceivedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), Status: store.StatusQueued,
		}); err != nil {
			t.Fatal(err)
		}
	}

	srv := httptest.NewServer(a.handler)
	t.Cleanup(srv.Close)
	scoped := openLive(t, a, srv, tn.scoped)
	unscoped := openLive(t, a, srv, tn.unscoped)

	a.hub.Notify(store.EventMailReceived, map[string]any{"id": "msg-beta", "domain": "beta.example", "subject": "beta secret by domain"})
	a.hub.Notify(store.EventMailDelivered, map[string]any{"id": "msg-beta", "to": "beta secret by message"})
	a.hub.Notify(store.EventMailReceived, map[string]any{"id": "msg-unknown", "subject": "secret of a message that is gone"})
	a.hub.Notify("some_future_event", map[string]any{"detail": "secret without a domain"})
	a.hub.Notify("maintenance", map[string]any{"draining": true})
	a.hub.Notify(store.EventMailDelivered, map[string]any{"id": "msg-alpha", "to": "alpha by message"})
	a.hub.Notify(store.EventMailReceived, map[string]any{"id": "msg-alpha", "domain": "alpha.example", "subject": "alpha done"})

	got := strings.Join(collectUntil(t, scoped, "alpha done"), "\n")
	if strings.Contains(got, "secret") {
		t.Fatalf("SECURITY: a user scoped to alpha.example received another tenant's event:\n%s", got)
	}
	for _, want := range []string{"alpha by message", `"draining":true`} {
		if !strings.Contains(got, want) {
			t.Errorf("the scoped stream is missing %q:\n%s", want, got)
		}
	}

	all := strings.Join(collectUntil(t, unscoped, "alpha done"), "\n")
	for _, want := range []string{"beta secret by domain", "beta secret by message", "secret without a domain", "alpha done"} {
		if !strings.Contains(all, want) {
			t.Errorf("an operator without allowed_domains sees the whole node, but %q is missing:\n%s", want, all)
		}
	}
}
