package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/xeron-be/xeron-mx/internal/config"
)

const (
	discoveryRetryBase = 15 * time.Second
	discoveryRetryMax  = 5 * time.Minute
)

var (
	ErrNotReady = errors.New("oidc: the identity provider has not been reached yet")

	ErrEmailUnverified = errors.New("oidc: the provider did not assert that this address is verified")
)

type Provider struct {
	cfg         config.OIDCConfig
	redirectURL string
	log         *slog.Logger

	mu       sync.RWMutex
	verifier *coreoidc.IDTokenVerifier
	oauth    *oauth2.Config
	lastErr  error
}

func New(cfg config.OIDCConfig, redirectURL string, log *slog.Logger) *Provider {
	return &Provider{cfg: cfg, redirectURL: redirectURL, log: log}
}

func (p *Provider) Enabled() bool { return p.cfg.Enabled }

func (p *Provider) Issuer() string { return p.cfg.Issuer }

func (p *Provider) RedirectURL() string { return p.redirectURL }

func (p *Provider) AllowPasswordLogin() bool { return p.cfg.AllowPasswordLogin }

func (p *Provider) Ready() (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.verifier != nil, p.lastErr
}

func (p *Provider) Run(ctx context.Context) {
	if !p.Enabled() {
		return
	}

	delay := discoveryRetryBase
	for {
		if err := p.discover(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.mu.Lock()
			p.lastErr = err
			p.mu.Unlock()
			p.log.Error("oidc: could not reach the identity provider, retrying",
				"issuer", p.cfg.Issuer, "retry_in", delay.String(), "error", err)

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			if delay *= 2; delay > discoveryRetryMax {
				delay = discoveryRetryMax
			}
			continue
		}

		p.log.Info("oidc ready",
			"issuer", p.cfg.Issuer, "client_id", p.cfg.ClientID,
			"redirect_url", p.redirectURL, "auto_provision", p.cfg.AutoProvision)
		return
	}
}

func (p *Provider) discover(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	provider, err := coreoidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return err
	}

	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{coreoidc.ScopeOpenID, "email", "profile"}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifier = provider.Verifier(&coreoidc.Config{ClientID: p.cfg.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.redirectURL,
		Scopes:       scopes,
	}
	p.lastErr = nil
	return nil
}

func (p *Provider) AuthCodeURL(state, nonce, verifier string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.oauth == nil {
		return "", ErrNotReady
	}
	opts := []oauth2.AuthCodeOption{
		coreoidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	}
	if p.cfg.HostedDomain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.cfg.HostedDomain))
	}
	return p.oauth.AuthCodeURL(state, opts...), nil
}

type Identity struct {
	Subject string
	Issuer  string
	Email   string
	Name    string
	Role    string
}

type claims struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	Name          string `json:"name"`
	PreferredName string `json:"preferred_username"`
	UPN           string `json:"upn"`
	HostedDomain  string `json:"hd"`
}

func (p *Provider) Exchange(ctx context.Context, code, nonce, verifier string) (*Identity, error) {
	p.mu.RLock()
	oauthCfg, idVerifier := p.oauth, p.verifier
	p.mu.RUnlock()
	if oauthCfg == nil || idVerifier == nil {
		return nil, ErrNotReady
	}

	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: the code exchange failed: %w", err)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("oidc: the provider returned no id_token")
	}

	idToken, err := idVerifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: the id_token did not verify: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, errors.New("oidc: the id_token nonce does not match this sign-in")
	}

	var c claims
	if err := idToken.Claims(&c); err != nil {
		return nil, fmt.Errorf("oidc: could not read the id_token claims: %w", err)
	}
	var rawClaims map[string]any
	_ = idToken.Claims(&rawClaims)

	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" {
		if strings.Contains(c.PreferredName, "@") {
			email = strings.ToLower(strings.TrimSpace(c.PreferredName))
		} else if strings.Contains(c.UPN, "@") {
			email = strings.ToLower(strings.TrimSpace(c.UPN))
		}
	}
	if email == "" {
		return nil, errors.New("oidc: the provider returned no email claim; " +
			"add the email scope to this client")
	}

	if c.EmailVerified == nil {
		if !p.cfg.SkipEmailVerified {
			return nil, fmt.Errorf("%w: no email_verified claim was present", ErrEmailUnverified)
		}
	} else if !*c.EmailVerified {
		return nil, fmt.Errorf("%w: %s", ErrEmailUnverified, email)
	}

	if p.cfg.HostedDomain != "" {
		if !strings.EqualFold(c.HostedDomain, p.cfg.HostedDomain) {
			return nil, fmt.Errorf("oidc: the provider did not assert the expected hosted domain %q", p.cfg.HostedDomain)
		}
	}

	name := c.Name
	if name == "" {
		name = c.PreferredName
	}
	role := p.RoleFromClaims(rawClaims)

	return &Identity{
		Subject: idToken.Subject,
		Issuer:  idToken.Issuer,
		Email:   email,
		Name:    name,
		Role:    role,
	}, nil
}

func (p *Provider) MayProvision(email string) bool {
	if !p.cfg.AutoProvision {
		return false
	}
	if len(p.cfg.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	for _, allowed := range p.cfg.AllowedDomains {
		if strings.EqualFold(allowed, domain) {
			return true
		}
	}
	return false
}

func (p *Provider) DefaultRole() string {
	if p.cfg.DefaultRole == "" {
		return config.RoleViewer
	}
	return p.cfg.DefaultRole
}

func (p *Provider) RoleFromClaims(raw map[string]any) string {
	if raw == nil {
		return p.DefaultRole()
	}
	claimName := p.cfg.RolesClaim
	if claimName == "" {
		claimName = "groups"
	}
	var extracted []string
	if val, ok := raw[claimName]; ok {
		extracted = toStringSlice(val)
	}
	if len(extracted) == 0 && claimName != "roles" {
		if val, ok := raw["roles"]; ok {
			extracted = toStringSlice(val)
		}
	}

	for _, g := range extracted {
		for _, ag := range p.cfg.AdminGroups {
			if strings.EqualFold(g, ag) {
				return config.RoleAdmin
			}
		}
	}
	for _, g := range extracted {
		for _, og := range p.cfg.OperatorGroups {
			if strings.EqualFold(g, og) {
				return config.RoleOperator
			}
		}
	}
	for _, g := range extracted {
		for _, vg := range p.cfg.ViewerGroups {
			if strings.EqualFold(g, vg) {
				return config.RoleViewer
			}
		}
	}
	return p.DefaultRole()
}

func toStringSlice(val any) []string {
	switch v := val.(type) {
	case []any:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				res = append(res, s)
			}
		}
		return res
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return nil
	}
}
