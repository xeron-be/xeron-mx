package config

import (
	"strings"
	"testing"
	"time"
)

func base() Config {
	c := Default()
	c.DataDir = "/var/lib/xeronmx"
	return c
}

func TestDefaultsAreValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
}

func TestWebhookSettingsMustMakeSense(t *testing.T) {
	cases := []struct {
		name  string
		mutfn func(*Config)
		want  string
	}{
		{"no workers", func(c *Config) { c.Webhooks.Workers = 0 }, "workers"},
		{"no attempts", func(c *Config) { c.Webhooks.MaxAttempts = 0 }, "max_attempts"},
		{"max below base", func(c *Config) {
			c.Webhooks.RetryBase = time.Hour
			c.Webhooks.RetryMax = time.Minute
		}, "retry_max"},
		{"no timeout", func(c *Config) { c.Webhooks.Timeout = 0 }, "timeout"},
	}
	for _, tc := range cases {
		c := base()
		tc.mutfn(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name %s", tc.name, err, tc.want)
		}
	}
}

func TestWebhookSettingsAreIgnoredWhenOff(t *testing.T) {
	c := base()
	c.Webhooks.Enabled = false
	c.Webhooks.Workers = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("settings for a disabled subsystem were validated: %v", err)
	}
}

func TestOIDCValidation(t *testing.T) {
	valid := func() Config {
		c := base()
		c.HTTP.BaseURL = "https://mx2.example.com"
		c.OIDC = OIDCConfig{
			Enabled: true, Issuer: "https://id.example.com", ClientID: "xeronmx",
			DefaultRole: RoleViewer, Scopes: []string{"openid", "email"},
		}
		return c
	}

	ok := valid()
	if err := ok.Validate(); err != nil {
		t.Fatalf("a reasonable OIDC configuration was rejected: %v", err)
	}

	cases := []struct {
		name  string
		mutfn func(*Config)
		want  string
	}{
		{"no issuer", func(c *Config) { c.OIDC.Issuer = "" }, "issuer"},
		{"http issuer", func(c *Config) { c.OIDC.Issuer = "http://id.example.com" }, "https"},
		{"no client id", func(c *Config) { c.OIDC.ClientID = "" }, "client_id"},
		{"nowhere to return to", func(c *Config) {
			c.HTTP.BaseURL = ""
			c.OIDC.RedirectURL = ""
		}, "redirect_url"},
		{"invented role", func(c *Config) { c.OIDC.DefaultRole = "superuser" }, "default_role"},
		{"domain with an at sign", func(c *Config) {
			c.OIDC.AllowedDomains = []string{"@example.com"}
		}, "allowed_domains"},
	}
	for _, tc := range cases {
		c := valid()
		tc.mutfn(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name %s", tc.name, err, tc.want)
		}
	}
}

func TestOIDCRefusesAPlaintextIssuer(t *testing.T) {
	c := base()
	c.HTTP.BaseURL = "https://mx2.example.com"
	c.OIDC = OIDCConfig{
		Enabled: true, Issuer: "http://localhost:8081/realms/x",
		ClientID: "x", DefaultRole: RoleViewer,
	}
	if err := c.Validate(); err == nil {
		t.Fatal("SECURITY: a plaintext OIDC issuer was accepted")
	}
}

func TestOIDCRedirectURLIsDerivedFromBaseURL(t *testing.T) {
	c := base()
	c.HTTP.BaseURL = "https://mx2.example.com/"
	got := c.OIDCRedirectURL()
	want := "https://mx2.example.com/api/v1/auth/oidc/callback"
	if got != want {
		t.Fatalf("OIDCRedirectURL = %q, want %q", got, want)
	}

	c.OIDC.RedirectURL = "https://elsewhere.example.com/cb"
	if got := c.OIDCRedirectURL(); got != "https://elsewhere.example.com/cb" {
		t.Fatalf("an explicit redirect_url was overridden: %q", got)
	}
}

func TestClusterValidation(t *testing.T) {
	valid := func() Config {
		c := base()
		c.Cluster = ClusterConfig{
			Enabled: true, Secret: "a secret of sixteen or more",
			Role: NodeFollower, Interval: 30 * time.Second, Timeout: 10 * time.Second,
			Peers: []string{"https://mx1.example.com"},
		}
		return c
	}

	ok := valid()
	if err := ok.Validate(); err != nil {
		t.Fatalf("a reasonable cluster configuration was rejected: %v", err)
	}

	cases := []struct {
		name  string
		mutfn func(*Config)
		want  string
	}{
		{"no secret", func(c *Config) { c.Cluster.Secret = "" }, "secret"},
		{"short secret", func(c *Config) { c.Cluster.Secret = "hunter2" }, "16"},
		{"invented role", func(c *Config) { c.Cluster.Role = "leader" }, "role"},
		{"no interval", func(c *Config) { c.Cluster.Interval = 0 }, "interval"},
		{"peer is not a URL", func(c *Config) {
			c.Cluster.Peers = []string{"mx1.example.com"}
		}, "peers"},
		{"sync with nobody to sync from", func(c *Config) {
			c.Cluster.SyncConfig = true
			c.Cluster.Peers = nil
		}, "sync_config"},
	}
	for _, tc := range cases {
		c := valid()
		tc.mutfn(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name %s", tc.name, err, tc.want)
		}
	}
}

func TestClusterRefusesToRunWithoutASecret(t *testing.T) {
	c := base()
	c.Cluster = ClusterConfig{Enabled: true, Role: NodeFollower,
		Interval: time.Second, Timeout: time.Second}
	if err := c.Validate(); err == nil {
		t.Fatal("SECURITY: clustering was enabled with no shared secret")
	}
}

func TestClusterRoleFollowsPrimaryNodeID(t *testing.T) {
	c := base()
	c.Cluster = ClusterConfig{
		Enabled: true, Secret: "a secret of sixteen or more",
		Role: NodeFollower, PrimaryNodeID: "xeronmx-0",
		Interval: time.Second, Timeout: time.Second,
	}

	c.Cluster.NodeID = "xeronmx-0"
	if got := c.ClusterRole(); got != NodePrimary {
		t.Fatalf("the named primary resolved to %q", got)
	}
	c.Cluster.NodeID = "xeronmx-1"
	if got := c.ClusterRole(); got != NodeFollower {
		t.Fatalf("a node that is not the named primary resolved to %q", got)
	}
}

func TestClusterRoleFallsBackToTheExplicitRole(t *testing.T) {
	c := base()
	c.Cluster.Role = NodePrimary
	if got := c.ClusterRole(); got != NodePrimary {
		t.Fatalf("ClusterRole = %q with no primary_node_id set", got)
	}
	c.Cluster.Role = "nonsense"
	if got := c.ClusterRole(); got != NodeFollower {
		t.Fatalf("ClusterRole = %q for an unknown role, want follower", got)
	}
}

func TestClusterRoleValidationIsSkippedWhenThePrimaryIsNamed(t *testing.T) {
	c := base()
	c.Cluster = ClusterConfig{
		Enabled: true, Secret: "a secret of sixteen or more",
		Role: "", PrimaryNodeID: "xeronmx-0",
		Interval: time.Second, Timeout: time.Second,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("naming the primary should make role optional: %v", err)
	}
}

func TestClusterNodeIDFallsBackToTheHostname(t *testing.T) {
	c := base()
	c.Cluster.NodeID = "explicit"
	if got := c.ClusterNodeID(); got != "explicit" {
		t.Fatalf("ClusterNodeID = %q", got)
	}
	c.Cluster.NodeID = ""
	if got := c.ClusterNodeID(); got == "" {
		t.Fatal("ClusterNodeID is empty with no hostname to fall back to")
	}
}

func TestSplitListTrimsAndDropsEmpties(t *testing.T) {
	got := splitList(" a.example.com , ,b.example.com ")
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("splitList = %q", got)
	}
}

func TestProxyProtocolRangesAreValidated(t *testing.T) {
	c := base()
	c.SMTP.ProxyProtocolTrusted = []string{"10.0.0.0/8", "192.0.2.7"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid ranges were refused: %v", err)
	}
	c.SMTP.ProxyProtocolTrusted = []string{"10.0.0.0/8", "load-balancer"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "proxy_protocol_trusted") {
		t.Fatalf("Validate = %v; want an error naming smtp.proxy_protocol_trusted", err)
	}
}

func TestProxyProtocolRangesFromTheEnvironment(t *testing.T) {
	t.Setenv("XERONMX_SMTP_PROXY_PROTOCOL_TRUSTED", "10.0.0.0/8,192.0.2.7")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SMTP.ProxyProtocolTrusted) != 2 || c.SMTP.ProxyProtocolTrusted[1] != "192.0.2.7" {
		t.Fatalf("proxy_protocol_trusted = %v", c.SMTP.ProxyProtocolTrusted)
	}
}

func TestPrivateDestinationsAreRefusedUnlessAllowed(t *testing.T) {
	if Default().Queue.AllowPrivateDestinations {
		t.Fatal("private destinations are allowed by default")
	}
	t.Setenv("XERONMX_QUEUE_ALLOW_PRIVATE_DESTINATIONS", "true")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Queue.AllowPrivateDestinations {
		t.Fatal("XERONMX_QUEUE_ALLOW_PRIVATE_DESTINATIONS=true was ignored")
	}
}
