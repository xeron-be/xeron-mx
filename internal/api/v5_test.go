package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/cluster"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/oidc"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/webhook"
)

func (a *testAPI) doAuth(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

func (a *testAPI) mintToken(t *testing.T, cookie *http.Cookie, name, role string) string {
	t.Helper()
	rec := a.do(t, "POST", "/api/v1/tokens", map[string]string{"name": name, "role": role}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("token creation returned %d: %s", rec.Code, rec.Body.String())
	}
	secret, _ := decodeBody(t, rec)["secret"].(string)
	if secret == "" {
		t.Fatal("no secret came back from token creation")
	}
	return secret
}

func TestTokenIsShownExactlyOnce(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/tokens", map[string]string{"name": "ci"}, cookie)
	body := decodeBody(t, rec)
	secret, _ := body["secret"].(string)
	if !strings.HasPrefix(secret, "xmx_") {
		t.Fatalf("secret = %q, want the xmx_ prefix", secret)
	}

	rec = a.do(t, "GET", "/api/v1/tokens", nil, cookie)
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("SECURITY: listing the tokens returned the secret again")
	}
	if !strings.Contains(rec.Body.String(), secret[:PrefixLen]) {
		t.Error("the listing does not show the prefix, so two tokens cannot be told apart")
	}
}

const PrefixLen = 12

func TestTokenAuthenticatesAsItsOwner(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "ci", store.RoleAdmin)

	rec := a.doAuth(t, "GET", "/api/v1/auth/me", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer auth returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["email"] != "admin@test.example" {
		t.Fatalf("the token authenticated as %v, want the account that created it", body["email"])
	}
	via, _ := body["via_token"].(map[string]any)
	if via == nil || via["name"] != "ci" {
		t.Fatalf("the response does not say which token was used: %v", body["via_token"])
	}
}

func TestViewerTokenCannotWrite(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "readonly", store.RoleViewer)

	if rec := a.doAuth(t, "GET", "/api/v1/status", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("a read-only token could not read: %d", rec.Code)
	}

	rec := a.doAuth(t, "POST", "/api/v1/domains", token, map[string]any{
		"name": "evil.test", "primary_host": "mail.evil.test",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: a read-only token created a domain (status %d)", rec.Code)
	}
}

func TestTokenIsNarrowedWhenItsOwnerIsDemoted(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "was-admin", store.RoleAdmin)

	if _, err := a.db.ExecContext(context.Background(),
		`UPDATE users SET role = 'viewer'`); err != nil {
		t.Fatal(err)
	}

	rec := a.doAuth(t, "POST", "/api/v1/domains", token, map[string]any{
		"name": "late.test", "primary_host": "mail.late.test",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: an admin token still wrote after its owner was demoted (status %d)", rec.Code)
	}
}

func TestTokenDiesWithItsOwner(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "orphan", store.RoleAdmin)

	if _, err := a.db.ExecContext(context.Background(), `DELETE FROM users`); err != nil {
		t.Fatal(err)
	}

	rec := a.doAuth(t, "GET", "/api/v1/status", token, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: a token outlived the account that owned it (status %d)", rec.Code)
	}
}

func TestUnknownTokenIsRefused(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	rec := a.doAuth(t, "GET", "/api/v1/status", "xmx_thisisnotarealtokenatall", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: an invented token returned %d", rec.Code)
	}
}

func TestExpiredTokenIsRefused(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "stale", store.RoleViewer)

	if _, err := a.db.ExecContext(context.Background(),
		`UPDATE api_tokens SET expires_at = ?`,
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	rec := a.doAuth(t, "GET", "/api/v1/status", token, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: an expired token was accepted (status %d)", rec.Code)
	}
}

func TestRevokedTokenStopsImmediately(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	token := a.mintToken(t, cookie, "doomed", store.RoleViewer)

	list := decodeBody(t, a.do(t, "GET", "/api/v1/tokens", nil, cookie))
	tokens, _ := list["tokens"].([]any)
	first, _ := tokens[0].(map[string]any)
	id := int64(first["id"].(float64))

	if rec := a.do(t, "DELETE", "/api/v1/tokens/"+strconv.FormatInt(id, 10), nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("revoke returned %d", rec.Code)
	}
	if rec := a.doAuth(t, "GET", "/api/v1/status", token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: a revoked token still worked (status %d)", rec.Code)
	}
}

func TestTokenRequiresAName(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/tokens", map[string]string{"name": "  "}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unnamed token was accepted (status %d)", rec.Code)
	}
}

func TestTokenExpiryIsCapped(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/tokens", map[string]string{
		"name": "forever", "expires_in": "90000h",
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a ten-year token was accepted (status %d)", rec.Code)
	}
}

func TestTokenDefaultsToViewer(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "POST", "/api/v1/tokens", map[string]string{"name": "unspecified"}, cookie)
	tok, _ := decodeBody(t, rec)["token"].(map[string]any)
	if tok["role"] != store.RoleViewer {
		t.Fatalf("a token with no role asked for came back as %v; the safe default is viewer", tok["role"])
	}
}

func (a *testAPI) withWebhooks(t *testing.T) *webhook.Dispatcher {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := webhook.New(config.Default().Webhooks, a.db, a.Server.blobs, "mx2.test", log)
	a.Server.SetWebhooks(d)
	return d
}

func TestWebhookSecretNeverComesBack(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withWebhooks(t)

	rec := a.do(t, "POST", "/api/v1/webhooks", map[string]any{
		"name": "chat", "url": "https://hooks.test/x",
	}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	generated, _ := body["secret"].(string)
	if generated == "" {
		t.Fatal("no secret was generated; an unsigned subscription is the wrong default")
	}
	hook, _ := body["webhook"].(map[string]any)
	if hook["signed"] != true {
		t.Error("the subscription does not report itself as signed")
	}

	rec = a.do(t, "GET", "/api/v1/webhooks", nil, cookie)
	if strings.Contains(rec.Body.String(), generated) {
		t.Fatal("SECURITY: the signing secret was returned by the listing")
	}
	if strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatal("SECURITY: the listing carries a secret field at all")
	}
}

func TestWebhookAcceptsAnExplicitlyUnsignedSubscription(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withWebhooks(t)

	empty := ""
	rec := a.do(t, "POST", "/api/v1/webhooks", map[string]any{
		"name": "plain", "url": "https://hooks.test/x", "secret": &empty,
	}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	hook, _ := decodeBody(t, rec)["webhook"].(map[string]any)
	if hook["signed"] != false {
		t.Fatal("an explicitly empty secret still produced a signed subscription")
	}
}

func TestWebhookRejectsBadInput(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withWebhooks(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no name", map[string]any{"url": "https://hooks.test"}},
		{"no url", map[string]any{"name": "x"}},
		{"not a url", map[string]any{"name": "x", "url": "hooks.test"}},
		{"wrong scheme", map[string]any{"name": "x", "url": "ftp://hooks.test"}},
		{"unknown event", map[string]any{
			"name": "x", "url": "https://hooks.test", "events": []string{"mail_recieved"},
		}},
	}
	for _, tc := range cases {
		rec := a.do(t, "POST", "/api/v1/webhooks", tc.body, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
}

func TestWebhookEventCatalogueIsOffered(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "GET", "/api/v1/webhooks/events", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	cats, _ := decodeBody(t, rec)["categories"].([]any)
	if len(cats) == 0 {
		t.Fatal("the catalogue is empty, so nothing can be subscribed to from the UI")
	}
}

func TestWebhookTestReportsAFailingEndpointAsData(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withWebhooks(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusTeapot)
	}))
	defer srv.Close()

	created := decodeBody(t, a.do(t, "POST", "/api/v1/webhooks", map[string]any{
		"name": "teapot", "url": srv.URL,
	}, cookie))
	hook, _ := created["webhook"].(map[string]any)
	id := int64(hook["id"].(float64))

	rec := a.do(t, "POST", "/api/v1/webhooks/"+strconv.FormatInt(id, 10)+"/test", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 carrying the result", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["ok"] != false {
		t.Fatalf("ok = %v for an endpoint that answered 418", body["ok"])
	}
}

func TestWebhookWritesNeedAdmin(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withWebhooks(t)
	token := a.mintToken(t, cookie, "readonly", store.RoleViewer)

	rec := a.doAuth(t, "POST", "/api/v1/webhooks", token, map[string]any{
		"name": "x", "url": "https://hooks.test",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: a read-only token created a subscription (status %d)", rec.Code)
	}
}

func (a *testAPI) withCluster(t *testing.T, secret, nodeID string) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.ClusterConfig{
		Enabled: true, Secret: secret, Interval: 30 * time.Second, Timeout: time.Second,
		AdvertiseURL: "http://" + nodeID + ":8080",
	}
	n := cluster.New(cfg, nodeID, store.NodePrimary, "test", a.db, log)
	n.SetConfigSource(a.Server)
	a.Server.SetCluster(n)
}

func (a *testAPI) doSigned(t *testing.T, method, path, secret, peerID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.20:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cluster.SignRequest(req, secret, peerID, body)
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

const clusterSecret = "a shared secret at least sixteen"

func TestClusterEndpointsAre404WhenNotClustered(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	rec := a.doSigned(t, "POST", cluster.HeartbeatPath, clusterSecret, "mx-1", []byte(`{"node_id":"mx-1"}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 on an unclustered instance", rec.Code)
	}
}

func TestHeartbeatRequiresASignature(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	rec := a.do(t, "POST", cluster.HeartbeatPath, map[string]string{"node_id": "mx-1"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: an unsigned heartbeat returned %d", rec.Code)
	}
}

func TestHeartbeatIsNotReachableWithASession(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	rec := a.do(t, "POST", cluster.HeartbeatPath, map[string]string{"node_id": "mx-1"}, cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: an admin session reached the cluster endpoint (status %d)", rec.Code)
	}
}

func TestHeartbeatRejectsTheWrongSecret(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	rec := a.doSigned(t, "POST", cluster.HeartbeatPath, "a completely different secret",
		"mx-1", []byte(`{"node_id":"mx-1"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: a foreign secret was accepted (status %d)", rec.Code)
	}
}

func TestHeartbeatRecordsThePeerAndAnswersWithItself(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	body := []byte(`{"node_id":"mx-1","role":"follower","config_hash":"abc","queue_pending":4}`)
	rec := a.doSigned(t, "POST", cluster.HeartbeatPath, clusterSecret, "mx-1", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var mine cluster.Heartbeat
	if err := json.Unmarshal(rec.Body.Bytes(), &mine); err != nil {
		t.Fatalf("the answer is not a heartbeat: %v", err)
	}
	if mine.NodeID != "mx-0" {
		t.Fatalf("answered as %q, want this node", mine.NodeID)
	}

	nodes, err := a.db.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range nodes {
		if n.ID == "mx-1" && n.QueuePending == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the peer was not recorded: %+v", nodes)
	}
}

func TestClusterConfigNeedsASignature(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	if rec := a.do(t, "GET", cluster.ConfigPath, nil, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: the configuration was served to a session (status %d)", rec.Code)
	}

	rec := a.doSigned(t, "GET", cluster.ConfigPath, clusterSecret, "mx-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("a signed peer could not fetch the configuration: %d %s", rec.Code, rec.Body.String())
	}
	if yaml, _ := decodeBody(t, rec)["yaml"].(string); !strings.Contains(yaml, "version") {
		t.Errorf("the configuration document looks wrong: %q", yaml)
	}
}

func TestClusterStateSaysTheQueueIsNotShared(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	rec := a.do(t, "GET", "/api/v1/cluster", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["queue_is_shared"] != false {
		t.Fatal("the payload does not state that the queue is per-node; the UI would have to guess")
	}
	if body["node_id"] != "mx-0" {
		t.Fatalf("node_id = %v", body["node_id"])
	}
}

func TestClusterStateWhenDisabled(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)

	rec := a.do(t, "GET", "/api/v1/cluster", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if decodeBody(t, rec)["enabled"] != false {
		t.Fatal("an unclustered instance did not report clustering as off")
	}
}

func TestForgetNodeRefusesThisNode(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")

	rec := a.do(t, "DELETE", "/api/v1/cluster/nodes/mx-0", nil, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d; forgetting this node would only be undone on the next heartbeat", rec.Code)
	}
}

func TestConfigDriftIsReported(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	a.withCluster(t, clusterSecret, "mx-0")
	ctx := context.Background()

	ours, err := a.Server.ConfigHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.db.UpsertNode(ctx, &store.Node{ID: "mx-0", ConfigHash: ours, Role: store.NodePrimary}); err != nil {
		t.Fatal(err)
	}
	if err := a.db.UpsertNode(ctx, &store.Node{ID: "mx-1", ConfigHash: "somethingelse", Role: store.NodeFollower}); err != nil {
		t.Fatal(err)
	}

	body := decodeBody(t, a.do(t, "GET", "/api/v1/cluster", nil, cookie))
	if body["drifted"] != float64(1) {
		t.Fatalf("drifted = %v, want 1: a domain on one node and not another answers 550", body["drifted"])
	}
}

func TestConfigHashIsStableAndChangesWithTheConfiguration(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.setup(t)
	ctx := context.Background()

	first, err := a.Server.ConfigHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := a.Server.ConfigHash(ctx)
	if first != again {
		t.Fatal("the same configuration hashed differently twice; drift detection would be noise")
	}

	if rec := a.do(t, "POST", "/api/v1/domains", map[string]any{
		"name": "example.test", "primary_host": "mail.example.test",
	}, cookie); rec.Code != http.StatusCreated {
		t.Fatalf("could not add a domain: %d %s", rec.Code, rec.Body.String())
	}

	after, _ := a.Server.ConfigHash(ctx)
	if after == first {
		t.Fatal("adding a domain did not change the fingerprint; drift would never be noticed")
	}
}

func TestSetupStatusAdvertisesSignInMethods(t *testing.T) {
	a := newTestAPI(t)

	body := decodeBody(t, a.do(t, "GET", "/api/v1/setup", nil, nil))
	if body["password_login"] != true {
		t.Fatal("password login is not advertised on an instance with no provider")
	}
	sso, _ := body["oidc"].(map[string]any)
	if sso == nil || sso["enabled"] != false {
		t.Fatalf("oidc advertisement = %v", body["oidc"])
	}
	if strings.Contains(strings.ToLower(a.do(t, "GET", "/api/v1/setup", nil, nil).Body.String()), "issuer") {
		t.Fatal("SECURITY: the unauthenticated setup endpoint names the identity provider")
	}
}

func (a *testAPI) withOIDC(t *testing.T, cfg config.OIDCConfig) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a.Server.SetOIDC(oidc.New(cfg, "https://mx2.test/api/v1/auth/oidc/callback", log))
}

func TestPasswordLoginCanBeTurnedOff(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	a.withOIDC(t, config.OIDCConfig{
		Enabled: true, Issuer: "https://id.test", ClientID: "x",
		AllowPasswordLogin: false,
	})

	rec := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
		"email": "admin@test.example", "password": testPassword,
	}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("password login still worked with allow_password_login off (status %d)", rec.Code)
	}

	body := decodeBody(t, a.do(t, "GET", "/api/v1/setup", nil, nil))
	if body["password_login"] != false {
		t.Error("the login page is not told that the password form is gone")
	}
}

func TestDirectoryAccountHasNoPasswordPath(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	ctx := context.Background()

	if _, err := a.db.CreateOIDCUser(ctx, "sso@test.example", store.RoleAdmin,
		"https://id.test", "sub-1"); err != nil {
		t.Fatal(err)
	}

	for _, password := range []string{"", " ", testPassword} {
		rec := a.do(t, "POST", "/api/v1/auth/login", map[string]string{
			"email": "sso@test.example", "password": password,
		}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("SECURITY: a directory account signed in with %q (status %d)", password, rec.Code)
		}
	}
}

func TestSSOLoginRedirectsWhenTheProviderIsUnreachable(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	a.withOIDC(t, config.OIDCConfig{Enabled: true, Issuer: "https://id.test", ClientID: "x"})

	rec := a.do(t, "GET", "/api/v1/auth/oidc/login", nil, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect carrying a reason", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "sso_error=not_ready") {
		t.Fatalf("Location = %q, want a not_ready code the UI can translate", loc)
	}
}

func TestSSOCallbackWithoutStateIsRefused(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)
	a.withOIDC(t, config.OIDCConfig{Enabled: true, Issuer: "https://id.test", ClientID: "x"})

	rec := a.do(t, "GET", "/api/v1/auth/oidc/callback?code=stolen&state=guessed", nil, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "sso_error=state") {
		t.Fatalf("SECURITY: a callback with no matching cookie got %q", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("SECURITY: a forged callback started a session")
		}
	}
}

func TestSSOEndpointsAreInertWhenNotConfigured(t *testing.T) {
	a := newTestAPI(t)
	a.setup(t)

	rec := a.do(t, "GET", "/api/v1/auth/oidc/login", nil, nil)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "sso_error=not_configured") {
		t.Fatalf("Location = %q", loc)
	}
}
