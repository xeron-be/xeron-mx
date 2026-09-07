package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/xeron-be/xeron-mx/internal/config"
)

type fakeIDP struct {
	*httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any
}

func newIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.URL,
			"authorization_endpoint":                idp.URL + "/authorize",
			"token_endpoint":                        idp.URL + "/token",
			"jwks_uri":                              idp.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": "AQAB",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": idp.mint(t, idp.claims),
		})
	})

	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func (i *fakeIDP) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	signing := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func (i *fakeIDP) setClaims(sub, email string, verified *bool, nonce string) {
	c := map[string]any{
		"iss": i.URL, "aud": "xeronmx", "sub": sub,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce, "email": email, "name": "Test Person",
	}
	if verified != nil {
		c["email_verified"] = *verified
	}
	i.claims = c
}

func (i *fakeIDP) setCustomClaims(c map[string]any) {
	if _, ok := c["iss"]; !ok {
		c["iss"] = i.URL
	}
	if _, ok := c["aud"]; !ok {
		c["aud"] = "xeronmx"
	}
	if _, ok := c["exp"]; !ok {
		c["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = time.Now().Unix()
	}
	i.claims = c
}

func ready(t *testing.T, idp *fakeIDP, cfg config.OIDCConfig) *Provider {
	t.Helper()
	cfg.Enabled = true
	cfg.Issuer = idp.URL
	if cfg.ClientID == "" {
		cfg.ClientID = "xeronmx"
	}
	p := New(cfg, "https://mx2.test/api/v1/auth/oidc/callback",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.discover(context.Background()); err != nil {
		t.Fatalf("discovery against the fake provider failed: %v", err)
	}
	return p
}

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

func TestExchangeReturnsAVerifiedIdentity(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})

	verifier := oauth2.GenerateVerifier()
	idp.setClaims("sub-1", "Ops@Example.Com", yes(), "the-nonce")

	id, err := p.Exchange(context.Background(), "code", "the-nonce", verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Subject != "sub-1" {
		t.Errorf("subject = %q", id.Subject)
	}
	if id.Email != "ops@example.com" {
		t.Errorf("email = %q, want it lowercased", id.Email)
	}
	if id.Issuer != idp.URL {
		t.Errorf("issuer = %q", id.Issuer)
	}
}

func TestExchangeRefusesAMismatchedNonce(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setClaims("sub-1", "ops@example.com", yes(), "a-different-nonce")

	_, err := p.Exchange(context.Background(), "code", "the-nonce", oauth2.GenerateVerifier())
	if err == nil {
		t.Fatal("SECURITY: an id_token minted for another sign-in was accepted")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("err = %v, want it to name the nonce", err)
	}
}

func TestExchangeRefusesAnUnverifiedEmail(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setClaims("sub-1", "victim@example.com", no(), "n")

	_, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier())
	if !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("SECURITY: an unverified address was accepted (err = %v)", err)
	}
}

func TestExchangeRefusesAMissingEmailVerifiedClaim(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setClaims("sub-1", "someone@example.com", nil, "n")

	_, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier())
	if !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("SECURITY: a missing email_verified claim was treated as verified (err = %v)", err)
	}
	if !strings.Contains(err.Error(), "email_verified") {
		t.Errorf("the error does not tell the operator what to fix: %v", err)
	}
}

func TestExchangeRefusesAnIDTokenForAnotherClient(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setClaims("sub-1", "ops@example.com", yes(), "n")
	idp.claims["aud"] = "some-other-application"

	if _, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier()); err == nil {
		t.Fatal("SECURITY: an id_token issued to a different client was accepted")
	}
}

func TestExchangeRefusesAnExpiredIDToken(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setClaims("sub-1", "ops@example.com", yes(), "n")
	idp.claims["exp"] = time.Now().Add(-time.Hour).Unix()

	if _, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier()); err == nil {
		t.Fatal("SECURITY: an expired id_token was accepted")
	}
}

func TestExchangeRefusesATokenSignedByAnotherKey(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp.setClaims("sub-1", "ops@example.com", yes(), "n")
	idp.key = other

	if _, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier()); err == nil {
		t.Fatal("SECURITY: an id_token signed by an unknown key verified")
	}
}

func TestExchangeRefusesAnIDTokenWithNoEmail(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setClaims("sub-1", "", yes(), "n")

	_, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier())
	if err == nil {
		t.Fatal("an identity with no email was accepted; the account could not be addressed")
	}
	if !strings.Contains(err.Error(), "email scope") {
		t.Errorf("the error does not point at the fix: %v", err)
	}
}

func TestExchangeEntraIDWithoutEmailVerified(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{SkipEmailVerified: true})
	idp.setCustomClaims(map[string]any{
		"sub":                "entra-user-1",
		"preferred_username": "admin@myorg.onmicrosoft.com",
		"name":               "Entra Admin",
		"nonce":              "the-nonce",
	})

	id, err := p.Exchange(context.Background(), "code", "the-nonce", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "admin@myorg.onmicrosoft.com" {
		t.Errorf("email = %q, want admin@myorg.onmicrosoft.com", id.Email)
	}
	if id.Name != "Entra Admin" {
		t.Errorf("name = %q", id.Name)
	}
}

func TestExchangeEntraIDWithUPN(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{SkipEmailVerified: true})
	idp.setCustomClaims(map[string]any{
		"sub":   "entra-user-2",
		"upn":   "operator@tenant.com",
		"name":  "Tenant Operator",
		"nonce": "the-nonce",
	})

	id, err := p.Exchange(context.Background(), "code", "the-nonce", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "operator@tenant.com" {
		t.Errorf("email = %q, want operator@tenant.com", id.Email)
	}
}

func TestExchangeGoogleWorkspaceHostedDomain(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{HostedDomain: "company.com"})

	got, err := p.AuthCodeURL("s", "n", "v")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if !strings.Contains(got, "hd=company.com") {
		t.Errorf("AuthCodeURL = %q, want it to contain hd=company.com", got)
	}

	idp.setCustomClaims(map[string]any{
		"sub":            "google-user-1",
		"email":          "alice@company.com",
		"email_verified": true,
		"hd":             "company.com",
		"name":           "Alice Workspace",
		"nonce":          "n",
	})

	id, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "alice@company.com" {
		t.Errorf("email = %q", id.Email)
	}
}

func TestExchangeGoogleWorkspaceHostedDomainMismatch(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{HostedDomain: "company.com"})
	idp.setCustomClaims(map[string]any{
		"sub":            "google-user-2",
		"email":          "bob@other.com",
		"email_verified": true,
		"hd":             "other.com",
		"name":           "Bob Outsider",
		"nonce":          "n",
	})

	_, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier())
	if err == nil {
		t.Fatal("SECURITY: token from unauthorized hosted domain was accepted")
	}
}

func TestExchangeOktaStandard(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	idp.setCustomClaims(map[string]any{
		"sub":                "00u1234567890",
		"email":              "admin@oktadomain.com",
		"email_verified":     true,
		"preferred_username": "admin@oktadomain.com",
		"name":               "Okta Admin",
		"nonce":              "n",
	})

	id, err := p.Exchange(context.Background(), "code", "n", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "admin@oktadomain.com" {
		t.Errorf("email = %q", id.Email)
	}
	if id.Name != "Okta Admin" {
		t.Errorf("name = %q", id.Name)
	}
}

func TestNotReadyBeforeDiscovery(t *testing.T) {
	p := New(config.OIDCConfig{Enabled: true, Issuer: "https://unreachable.invalid", ClientID: "x"},
		"https://mx2.test/cb", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if ok, _ := p.Ready(); ok {
		t.Fatal("the provider claims to be ready before discovery")
	}
	if _, err := p.AuthCodeURL("s", "n", "v"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("AuthCodeURL before discovery = %v, want ErrNotReady", err)
	}
	if _, err := p.Exchange(context.Background(), "c", "n", "v"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Exchange before discovery = %v, want ErrNotReady", err)
	}
}

func TestAuthCodeURLCarriesPKCEAndNonce(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})

	verifier := oauth2.GenerateVerifier()
	got, err := p.AuthCodeURL("the-state", "the-nonce", verifier)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"state=the-state", "nonce=the-nonce",
		"code_challenge=", "code_challenge_method=S256",
		"client_id=xeronmx",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the authorization URL does not carry %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, verifier) {
		t.Fatal("SECURITY: the PKCE verifier was sent to the provider instead of its challenge")
	}
}

func TestDefaultScopes(t *testing.T) {
	idp := newIDP(t)
	p := ready(t, idp, config.OIDCConfig{})
	got, err := p.AuthCodeURL("s", "n", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "scope=openid") || !strings.Contains(got, "email") {
		t.Fatalf("the default scopes do not include openid and email:\n%s", got)
	}
}

func TestMayProvision(t *testing.T) {
	cases := []struct {
		name  string
		cfg   config.OIDCConfig
		email string
		want  bool
	}{
		{"off by default", config.OIDCConfig{}, "a@example.com", false},
		{"on, no restriction", config.OIDCConfig{AutoProvision: true}, "a@example.com", true},
		{"on, allowed domain", config.OIDCConfig{
			AutoProvision: true, AllowedDomains: []string{"example.com"},
		}, "a@Example.COM", true},
		{"on, other domain", config.OIDCConfig{
			AutoProvision: true, AllowedDomains: []string{"example.com"},
		}, "a@evil.test", false},
		{"on, not an address", config.OIDCConfig{
			AutoProvision: true, AllowedDomains: []string{"example.com"},
		}, "notanaddress", false},
	}
	for _, tc := range cases {
		p := New(tc.cfg, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if got := p.MayProvision(tc.email); got != tc.want {
			t.Errorf("%s: MayProvision(%q) = %v, want %v", tc.name, tc.email, got, tc.want)
		}
	}
}

func TestDefaultRoleIsViewer(t *testing.T) {
	p := New(config.OIDCConfig{}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := p.DefaultRole(); got != config.RoleViewer {
		t.Fatalf("DefaultRole = %q with nothing configured; the safe default is viewer", got)
	}
}

func TestAllowPasswordLoginIsReported(t *testing.T) {
	p := New(config.OIDCConfig{AllowPasswordLogin: true}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !p.AllowPasswordLogin() {
		t.Fatal("AllowPasswordLogin does not report what was configured")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	p := New(config.OIDCConfig{Enabled: true, Issuer: "https://unreachable.invalid", ClientID: "x"},
		"https://mx2.test/cb", slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not stop when its context was cancelled; shutdown would hang")
	}
}

func TestRoleFromClaims(t *testing.T) {
	cfg := config.OIDCConfig{
		DefaultRole:    config.RoleViewer,
		AdminGroups:    []string{"corp-admins"},
		OperatorGroups: []string{"mail-ops"},
		ViewerGroups:   []string{"observers"},
	}
	p := New(cfg, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if role := p.RoleFromClaims(map[string]any{"groups": []string{"corp-admins"}}); role != config.RoleAdmin {
		t.Fatalf("expected admin, got %q", role)
	}
	if role := p.RoleFromClaims(map[string]any{"groups": []string{"mail-ops"}}); role != config.RoleOperator {
		t.Fatalf("expected operator, got %q", role)
	}
	if role := p.RoleFromClaims(map[string]any{"groups": []string{"observers"}}); role != config.RoleViewer {
		t.Fatalf("expected viewer, got %q", role)
	}
	if role := p.RoleFromClaims(map[string]any{"groups": []string{"other"}}); role != config.RoleViewer {
		t.Fatalf("expected default viewer, got %q", role)
	}
	if role := p.RoleFromClaims(nil); role != config.RoleViewer {
		t.Fatalf("expected default viewer for nil claims, got %q", role)
	}
}
