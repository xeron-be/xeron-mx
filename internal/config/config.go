package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir     string            `yaml:"data_dir"`
	SMTP        SMTPConfig        `yaml:"smtp"`
	HTTP        HTTPConfig        `yaml:"http"`
	Queue       QueueConfig       `yaml:"queue"`
	Health      HealthConfig      `yaml:"health"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Spam        SpamConfig        `yaml:"spam"`
	Outbound    OutboundConfig    `yaml:"outbound"`
	Alerts      AlertConfig       `yaml:"alerts"`
	Backup      BackupConfig      `yaml:"backup"`
	Webhooks    WebhooksConfig    `yaml:"webhooks"`
	OIDC        OIDCConfig        `yaml:"oidc"`
	Cluster     ClusterConfig     `yaml:"cluster"`
	Log         LogConfig         `yaml:"log"`
	DNSBL       DNSBLConfig       `yaml:"dnsbl"`
	ClamAV      ClamAVConfig      `yaml:"clamav"`
	Maintenance MaintenanceConfig `yaml:"maintenance"`
}

type MaintenanceConfig struct {
	Drain bool `yaml:"drain"`
}

type WebhooksConfig struct {
	Enabled bool `yaml:"enabled"`

	Workers int `yaml:"workers"`

	Timeout time.Duration `yaml:"timeout"`

	MaxAttempts int `yaml:"max_attempts"`

	RetryBase time.Duration `yaml:"retry_base"`
	RetryMax  time.Duration `yaml:"retry_max"`

	Retention time.Duration `yaml:"retention"`
}

type OIDCConfig struct {
	Enabled bool `yaml:"enabled"`

	Issuer string `yaml:"issuer"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	RedirectURL string `yaml:"redirect_url"`

	Scopes []string `yaml:"scopes"`

	AutoProvision bool `yaml:"auto_provision"`

	DefaultRole string `yaml:"default_role"`

	AllowedDomains []string `yaml:"allowed_domains"`

	AllowPasswordLogin bool `yaml:"allow_password_login"`

	SkipEmailVerified bool `yaml:"skip_email_verified"`

	HostedDomain string `yaml:"hosted_domain"`

	RolesClaim     string   `yaml:"roles_claim"`
	AdminGroups    []string `yaml:"admin_groups"`
	OperatorGroups []string `yaml:"operator_groups"`
	ViewerGroups   []string `yaml:"viewer_groups"`
}

type ClusterConfig struct {
	Enabled bool `yaml:"enabled"`

	NodeID string `yaml:"node_id"`

	Role string `yaml:"role"`

	// PrimaryNodeID names the primary node for cluster sync under Kubernetes StatefulSet.
	// A shared configuration file is given to each node, which determines its role by comparing its node ID.
	PrimaryNodeID string `yaml:"primary_node_id"`

	AdvertiseURL string `yaml:"advertise_url"`

	Peers []string `yaml:"peers"`

	Secret string `yaml:"secret"`

	Interval time.Duration `yaml:"interval"`

	Timeout time.Duration `yaml:"timeout"`

	SyncConfig bool `yaml:"sync_config"`
}

type SpamConfig struct {
	Enabled bool `yaml:"enabled"`

	URL      string        `yaml:"url"`
	Password string        `yaml:"password"`
	Timeout  time.Duration `yaml:"timeout"`

	MaxSizeBytes int64 `yaml:"max_size_bytes"`

	RejectEnabled bool `yaml:"reject_enabled"`

	DeferEnabled bool `yaml:"defer_enabled"`
}

type DNSBLConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Zones     []string      `yaml:"zones"`
	Timeout   time.Duration `yaml:"timeout"`
	Whitelist []string      `yaml:"whitelist"`
}

type ClamAVConfig struct {
	Enabled bool          `yaml:"enabled"`
	Addr    string        `yaml:"addr"`
	Timeout time.Duration `yaml:"timeout"`
	Action  string        `yaml:"action"`
}

type OutboundConfig struct {
	Enabled bool `yaml:"enabled"`

	Addr string `yaml:"addr"`

	Mode string `yaml:"mode"`

	RelayHost     string `yaml:"relay_host"`
	RelayPort     int    `yaml:"relay_port"`
	RelayTLS      string `yaml:"relay_tls"`
	RelayUsername string `yaml:"relay_username"`
	RelayPassword string `yaml:"relay_password"`

	MaxMessageBytes int64 `yaml:"max_message_bytes"`

	MaxConnections int `yaml:"max_connections"`

	RequireTLS bool `yaml:"require_tls"`
}

type AlertConfig struct {
	Enabled          bool             `yaml:"enabled"`
	PrimaryDownAfter time.Duration    `yaml:"primary_down_after"`
	MinInterval      time.Duration    `yaml:"min_interval"`
	Webhook          WebhookConfig    `yaml:"webhook"`
	Email            AlertEmailConfig `yaml:"email"`
}

type WebhookConfig struct {
	URL     string        `yaml:"url"`
	Secret  string        `yaml:"secret"`
	Timeout time.Duration `yaml:"timeout"`
}

type AlertEmailConfig struct {
	To       []string `yaml:"to"`
	From     string   `yaml:"from"`
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	TLS      string   `yaml:"tls"`
}

type BackupConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Dir      string        `yaml:"dir"`
	Interval time.Duration `yaml:"interval"`
	Keep     int           `yaml:"keep"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`

	Token string `yaml:"token"`
}

type ACMEConfig struct {
	Enabled bool `yaml:"enabled"`

	Domains []string `yaml:"domains"`

	Email string `yaml:"email"`

	CacheDir string `yaml:"cache_dir"`

	ChallengeAddr string `yaml:"challenge_addr"`

	DirectoryURL string `yaml:"directory_url"`

	TermsAgreed bool `yaml:"terms_agreed"`

	// RenewBefore sets the certificate renewal window; must be shorter than the CA certificate lifetime.
	RenewBefore time.Duration `yaml:"renew_before"`
}

type SMTPConfig struct {
	Addr string `yaml:"addr"`

	Hostname string `yaml:"hostname"`

	MaxMessageBytes int64 `yaml:"max_message_bytes"`

	MaxRecipients int `yaml:"max_recipients"`

	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`

	MaxConnections int `yaml:"max_connections"`

	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
}

type HTTPConfig struct {
	Addr string `yaml:"addr"`

	BaseURL string `yaml:"base_url"`

	SessionTTL time.Duration `yaml:"session_ttl"`
	TLSCert    string        `yaml:"tls_cert"`
	TLSKey     string        `yaml:"tls_key"`

	ACME ACMEConfig `yaml:"acme"`
}

type QueueConfig struct {
	MaxMessages int64 `yaml:"max_messages"`

	MaxBytes int64 `yaml:"max_bytes"`

	MinFreeDiskBytes int64 `yaml:"min_free_disk_bytes"`

	Retention time.Duration `yaml:"retention"`

	Workers int `yaml:"workers"`

	RetryBase time.Duration `yaml:"retry_base"`
	RetryMax  time.Duration `yaml:"retry_max"`

	DeliveryTimeout time.Duration `yaml:"delivery_timeout"`
}

type HealthConfig struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`

	FailureThreshold int `yaml:"failure_threshold"`

	SuccessThreshold int `yaml:"success_threshold"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Default() Config {
	return Config{
		DataDir: "/var/lib/xeronmx",
		SMTP: SMTPConfig{
			Addr:            ":25",
			MaxMessageBytes: 50 << 20,
			MaxRecipients:   100,
			ReadTimeout:     5 * time.Minute,
			WriteTimeout:    5 * time.Minute,
			MaxConnections:  200,
		},
		HTTP: HTTPConfig{
			Addr:       ":8080",
			SessionTTL: 7 * 24 * time.Hour,
			ACME: ACMEConfig{
				ChallengeAddr: ":80",
			},
		},
		Queue: QueueConfig{
			MaxMessages:      100000,
			MaxBytes:         20 << 30,
			MinFreeDiskBytes: 1 << 30,
			Retention:        7 * 24 * time.Hour,
			Workers:          4,
			RetryBase:        1 * time.Minute,
			RetryMax:         2 * time.Hour,
			DeliveryTimeout:  5 * time.Minute,
		},
		Health: HealthConfig{
			Interval:         30 * time.Second,
			Timeout:          10 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 2,
		},
		Metrics: MetricsConfig{Enabled: true},
		Spam: SpamConfig{
			Timeout:      10 * time.Second,
			MaxSizeBytes: 10 << 20,
			DeferEnabled: true,
		},
		DNSBL: DNSBLConfig{
			Zones:   []string{"zen.spamhaus.org", "bl.spamcop.net"},
			Timeout: 2500 * time.Millisecond,
		},
		ClamAV: ClamAVConfig{
			Addr:    "localhost:3310",
			Timeout: 10 * time.Second,
			Action:  "quarantine",
		},
		Outbound: OutboundConfig{
			Addr:            ":587",
			Mode:            "relay",
			RelayPort:       587,
			RelayTLS:        "starttls",
			MaxMessageBytes: 50 << 20,
			MaxConnections:  100,
			RequireTLS:      true,
		},
		Alerts: AlertConfig{
			PrimaryDownAfter: 5 * time.Minute,
			MinInterval:      30 * time.Minute,
			Webhook:          WebhookConfig{Timeout: 10 * time.Second},
			Email:            AlertEmailConfig{Port: 587, TLS: "starttls"},
		},
		Backup: BackupConfig{Interval: 24 * time.Hour, Keep: 7},
		Webhooks: WebhooksConfig{
			Enabled:     true,
			Workers:     2,
			Timeout:     10 * time.Second,
			MaxAttempts: 8,
			RetryBase:   30 * time.Second,
			RetryMax:    time.Hour,
			Retention:   7 * 24 * time.Hour,
		},
		OIDC: OIDCConfig{
			Scopes:             []string{"openid", "email", "profile"},
			DefaultRole:        "viewer",
			AllowPasswordLogin: true,
		},
		Cluster: ClusterConfig{
			Role:     "follower",
			Interval: 30 * time.Second,
			Timeout:  10 * time.Second,
		},
		Log: LogConfig{Level: "info", Format: "json"},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", path, err)
			}
		case !os.IsNotExist(err):
			return cfg, fmt.Errorf("read %s: %w", path, err)
		}
	}

	applyEnv(&cfg)

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	num := func(key string, dst *int64) {
		if v, ok := os.LookupEnv(key); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*dst = n
			}
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := os.LookupEnv(key); ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(key); ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}

	str("XERONMX_DATA_DIR", &cfg.DataDir)
	str("XERONMX_SMTP_ADDR", &cfg.SMTP.Addr)
	str("XERONMX_SMTP_HOSTNAME", &cfg.SMTP.Hostname)
	str("XERONMX_SMTP_TLS_CERT", &cfg.SMTP.TLSCert)
	str("XERONMX_SMTP_TLS_KEY", &cfg.SMTP.TLSKey)
	num("XERONMX_SMTP_MAX_MESSAGE_BYTES", &cfg.SMTP.MaxMessageBytes)
	str("XERONMX_HTTP_ADDR", &cfg.HTTP.Addr)
	str("XERONMX_HTTP_BASE_URL", &cfg.HTTP.BaseURL)
	str("XERONMX_HTTP_TLS_CERT", &cfg.HTTP.TLSCert)
	str("XERONMX_HTTP_TLS_KEY", &cfg.HTTP.TLSKey)
	num("XERONMX_QUEUE_MAX_MESSAGES", &cfg.Queue.MaxMessages)
	num("XERONMX_QUEUE_MAX_BYTES", &cfg.Queue.MaxBytes)
	num("XERONMX_QUEUE_MIN_FREE_DISK_BYTES", &cfg.Queue.MinFreeDiskBytes)
	boolean("XERONMX_MAINTENANCE_DRAIN", &cfg.Maintenance.Drain)
	dur("XERONMX_QUEUE_RETENTION", &cfg.Queue.Retention)
	dur("XERONMX_HEALTH_INTERVAL", &cfg.Health.Interval)
	str("XERONMX_LOG_LEVEL", &cfg.Log.Level)
	str("XERONMX_LOG_FORMAT", &cfg.Log.Format)
	str("XERONMX_METRICS_TOKEN", &cfg.Metrics.Token)
	str("XERONMX_SPAM_URL", &cfg.Spam.URL)
	str("XERONMX_SPAM_PASSWORD", &cfg.Spam.Password)
	boolean("XERONMX_SPAM_ENABLED", &cfg.Spam.Enabled)
	boolean("XERONMX_SPAM_REJECT_ENABLED", &cfg.Spam.RejectEnabled)
	dur("XERONMX_SPAM_TIMEOUT", &cfg.Spam.Timeout)
	boolean("XERONMX_DNSBL_ENABLED", &cfg.DNSBL.Enabled)
	dur("XERONMX_DNSBL_TIMEOUT", &cfg.DNSBL.Timeout)
	if v, ok := os.LookupEnv("XERONMX_DNSBL_ZONES"); ok && v != "" {
		cfg.DNSBL.Zones = splitList(v)
	}
	if v, ok := os.LookupEnv("XERONMX_DNSBL_WHITELIST"); ok && v != "" {
		cfg.DNSBL.Whitelist = splitList(v)
	}
	boolean("XERONMX_CLAMAV_ENABLED", &cfg.ClamAV.Enabled)
	str("XERONMX_CLAMAV_ADDR", &cfg.ClamAV.Addr)
	dur("XERONMX_CLAMAV_TIMEOUT", &cfg.ClamAV.Timeout)
	str("XERONMX_CLAMAV_ACTION", &cfg.ClamAV.Action)
	boolean("XERONMX_OUTBOUND_ENABLED", &cfg.Outbound.Enabled)
	boolean("XERONMX_OUTBOUND_REQUIRE_TLS", &cfg.Outbound.RequireTLS)
	str("XERONMX_OUTBOUND_ADDR", &cfg.Outbound.Addr)
	str("XERONMX_OUTBOUND_MODE", &cfg.Outbound.Mode)
	if v, ok := os.LookupEnv("XERONMX_OUTBOUND_MAX_CONNECTIONS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Outbound.MaxConnections = n
		}
	}
	if v, ok := os.LookupEnv("XERONMX_SMTP_MAX_CONNECTIONS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SMTP.MaxConnections = n
		}
	}
	str("XERONMX_OUTBOUND_RELAY_HOST", &cfg.Outbound.RelayHost)
	str("XERONMX_OUTBOUND_RELAY_TLS", &cfg.Outbound.RelayTLS)
	str("XERONMX_OUTBOUND_RELAY_USERNAME", &cfg.Outbound.RelayUsername)
	str("XERONMX_OUTBOUND_RELAY_PASSWORD", &cfg.Outbound.RelayPassword)
	if v, ok := os.LookupEnv("XERONMX_OUTBOUND_RELAY_PORT"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Outbound.RelayPort = n
		}
	}
	boolean("XERONMX_BACKUP_ENABLED", &cfg.Backup.Enabled)
	str("XERONMX_BACKUP_DIR", &cfg.Backup.Dir)
	dur("XERONMX_BACKUP_INTERVAL", &cfg.Backup.Interval)
	if v, ok := os.LookupEnv("XERONMX_BACKUP_KEEP"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Backup.Keep = n
		}
	}
	boolean("XERONMX_ALERTS_ENABLED", &cfg.Alerts.Enabled)
	dur("XERONMX_ALERTS_PRIMARY_DOWN_AFTER", &cfg.Alerts.PrimaryDownAfter)
	dur("XERONMX_ALERTS_MIN_INTERVAL", &cfg.Alerts.MinInterval)
	str("XERONMX_ALERTS_WEBHOOK_URL", &cfg.Alerts.Webhook.URL)
	str("XERONMX_ALERTS_WEBHOOK_SECRET", &cfg.Alerts.Webhook.Secret)
	str("XERONMX_ALERTS_EMAIL_FROM", &cfg.Alerts.Email.From)
	str("XERONMX_ALERTS_EMAIL_HOST", &cfg.Alerts.Email.Host)
	str("XERONMX_ALERTS_EMAIL_USERNAME", &cfg.Alerts.Email.Username)
	str("XERONMX_ALERTS_EMAIL_PASSWORD", &cfg.Alerts.Email.Password)
	str("XERONMX_ALERTS_EMAIL_TLS", &cfg.Alerts.Email.TLS)
	if v, ok := os.LookupEnv("XERONMX_ALERTS_EMAIL_PORT"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Alerts.Email.Port = n
		}
	}
	if v, ok := os.LookupEnv("XERONMX_ALERTS_EMAIL_TO"); ok && v != "" {
		cfg.Alerts.Email.To = strings.Split(v, ",")
		for i := range cfg.Alerts.Email.To {
			cfg.Alerts.Email.To[i] = strings.TrimSpace(cfg.Alerts.Email.To[i])
		}
	}
	str("XERONMX_ACME_EMAIL", &cfg.HTTP.ACME.Email)
	str("XERONMX_ACME_CACHE_DIR", &cfg.HTTP.ACME.CacheDir)
	str("XERONMX_ACME_CHALLENGE_ADDR", &cfg.HTTP.ACME.ChallengeAddr)
	str("XERONMX_ACME_DIRECTORY_URL", &cfg.HTTP.ACME.DirectoryURL)
	dur("XERONMX_ACME_RENEW_BEFORE", &cfg.HTTP.ACME.RenewBefore)
	boolean("XERONMX_METRICS_ENABLED", &cfg.Metrics.Enabled)
	boolean("XERONMX_ACME_ENABLED", &cfg.HTTP.ACME.Enabled)
	boolean("XERONMX_ACME_TERMS_AGREED", &cfg.HTTP.ACME.TermsAgreed)
	if v, ok := os.LookupEnv("XERONMX_ACME_DOMAINS"); ok && v != "" {
		cfg.HTTP.ACME.Domains = strings.Split(v, ",")
		for i := range cfg.HTTP.ACME.Domains {
			cfg.HTTP.ACME.Domains[i] = strings.TrimSpace(cfg.HTTP.ACME.Domains[i])
		}
	}

	boolean("XERONMX_WEBHOOKS_ENABLED", &cfg.Webhooks.Enabled)
	dur("XERONMX_WEBHOOKS_TIMEOUT", &cfg.Webhooks.Timeout)
	dur("XERONMX_WEBHOOKS_RETENTION", &cfg.Webhooks.Retention)
	if v, ok := os.LookupEnv("XERONMX_WEBHOOKS_MAX_ATTEMPTS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Webhooks.MaxAttempts = n
		}
	}

	boolean("XERONMX_OIDC_ENABLED", &cfg.OIDC.Enabled)
	str("XERONMX_OIDC_ISSUER", &cfg.OIDC.Issuer)
	str("XERONMX_OIDC_CLIENT_ID", &cfg.OIDC.ClientID)
	str("XERONMX_OIDC_CLIENT_SECRET", &cfg.OIDC.ClientSecret)
	str("XERONMX_OIDC_REDIRECT_URL", &cfg.OIDC.RedirectURL)
	str("XERONMX_OIDC_DEFAULT_ROLE", &cfg.OIDC.DefaultRole)
	boolean("XERONMX_OIDC_AUTO_PROVISION", &cfg.OIDC.AutoProvision)
	boolean("XERONMX_OIDC_ALLOW_PASSWORD_LOGIN", &cfg.OIDC.AllowPasswordLogin)
	if v, ok := os.LookupEnv("XERONMX_OIDC_ALLOWED_DOMAINS"); ok && v != "" {
		cfg.OIDC.AllowedDomains = splitList(v)
	}
	if v, ok := os.LookupEnv("XERONMX_OIDC_SCOPES"); ok && v != "" {
		cfg.OIDC.Scopes = splitList(v)
	}
	str("XERONMX_OIDC_ROLES_CLAIM", &cfg.OIDC.RolesClaim)
	if v, ok := os.LookupEnv("XERONMX_OIDC_ADMIN_GROUPS"); ok && v != "" {
		cfg.OIDC.AdminGroups = splitList(v)
	}
	if v, ok := os.LookupEnv("XERONMX_OIDC_OPERATOR_GROUPS"); ok && v != "" {
		cfg.OIDC.OperatorGroups = splitList(v)
	}
	if v, ok := os.LookupEnv("XERONMX_OIDC_VIEWER_GROUPS"); ok && v != "" {
		cfg.OIDC.ViewerGroups = splitList(v)
	}

	boolean("XERONMX_CLUSTER_ENABLED", &cfg.Cluster.Enabled)
	str("XERONMX_CLUSTER_NODE_ID", &cfg.Cluster.NodeID)
	str("XERONMX_CLUSTER_ROLE", &cfg.Cluster.Role)
	str("XERONMX_CLUSTER_PRIMARY_NODE_ID", &cfg.Cluster.PrimaryNodeID)
	str("XERONMX_CLUSTER_ADVERTISE_URL", &cfg.Cluster.AdvertiseURL)
	str("XERONMX_CLUSTER_SECRET", &cfg.Cluster.Secret)
	dur("XERONMX_CLUSTER_INTERVAL", &cfg.Cluster.Interval)
	boolean("XERONMX_CLUSTER_SYNC_CONFIG", &cfg.Cluster.SyncConfig)
	if v, ok := os.LookupEnv("XERONMX_CLUSTER_PEERS"); ok && v != "" {
		cfg.Cluster.Peers = splitList(v)
	}

	if v, ok := os.LookupEnv("XERONMX_QUEUE_WORKERS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Queue.Workers = n
		}
	}
}

func (c *Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}
	if c.SMTP.MaxMessageBytes <= 0 {
		return fmt.Errorf("smtp.max_message_bytes must be positive")
	}

	if c.SMTP.MaxConnections < 0 {
		return fmt.Errorf("smtp.max_connections must not be negative (0 means no limit)")
	}
	if c.Outbound.MaxConnections < 0 {
		return fmt.Errorf("outbound.max_connections must not be negative (0 means no limit)")
	}
	if c.Queue.Workers <= 0 {
		return fmt.Errorf("queue.workers must be positive")
	}
	if c.Queue.RetryBase <= 0 || c.Queue.RetryMax < c.Queue.RetryBase {
		return fmt.Errorf("queue.retry_max must be >= queue.retry_base, both positive")
	}
	if c.Queue.Retention <= 0 {
		return fmt.Errorf("queue.retention must be positive")
	}
	if c.Queue.MinFreeDiskBytes < 0 {
		return fmt.Errorf("queue.min_free_disk_bytes must not be negative (0 to disable)")
	}
	if c.Health.FailureThreshold <= 0 || c.Health.SuccessThreshold <= 0 {
		return fmt.Errorf("health thresholds must be positive")
	}
	switch strings.ToLower(c.Log.Format) {
	case "json", "text":
	default:
		return fmt.Errorf("log.format must be json or text, got %q", c.Log.Format)
	}

	if (c.HTTP.TLSCert == "") != (c.HTTP.TLSKey == "") {
		return fmt.Errorf("http.tls_cert and http.tls_key must be set together")
	}
	if (c.SMTP.TLSCert == "") != (c.SMTP.TLSKey == "") {
		return fmt.Errorf("smtp.tls_cert and smtp.tls_key must be set together")
	}

	if c.HTTP.ACME.Enabled {
		if len(c.HTTP.ACME.Domains) == 0 {
			return fmt.Errorf("http.acme.domains must list at least one hostname when ACME is enabled")
		}
		for _, d := range c.HTTP.ACME.Domains {
			if d == "" || !strings.Contains(d, ".") {
				return fmt.Errorf("http.acme.domains contains %q, which is not a hostname", d)
			}
		}

		if !c.HTTP.ACME.TermsAgreed {
			return fmt.Errorf("http.acme.terms_agreed must be true to request certificates: " +
				"this accepts the CA subscriber agreement on your behalf")
		}
		if c.HTTP.TLSCert != "" {
			return fmt.Errorf("http.acme is enabled and http.tls_cert is set; use one or the other")
		}
		if c.HTTP.ACME.RenewBefore < 0 {
			return fmt.Errorf("http.acme.renew_before must not be negative")
		}
		if d := c.HTTP.ACME.RenewBefore; d > 0 && d < time.Hour {
			return fmt.Errorf("http.acme.renew_before is %s, which leaves no room to retry a "+
				"failed renewal before the certificate expires", d)
		}
	}

	if c.Spam.Enabled {
		if c.Spam.URL == "" {
			return fmt.Errorf("spam.url must be set when spam filtering is enabled")
		}
		if !strings.HasPrefix(c.Spam.URL, "http://") && !strings.HasPrefix(c.Spam.URL, "https://") {
			return fmt.Errorf("spam.url must start with http:// or https://, got %q", c.Spam.URL)
		}
		if c.Spam.Timeout <= 0 {
			return fmt.Errorf("spam.timeout must be positive")
		}
	}

	if c.DNSBL.Enabled {
		if c.DNSBL.Timeout <= 0 {
			return fmt.Errorf("dnsbl.timeout must be positive")
		}
		if len(c.DNSBL.Zones) == 0 {
			return fmt.Errorf("dnsbl.zones must not be empty when dnsbl is enabled")
		}
		for _, z := range c.DNSBL.Zones {
			if z == "" {
				return fmt.Errorf("dnsbl.zones contains an empty entry")
			}
		}
	}

	if c.ClamAV.Enabled {
		if c.ClamAV.Addr == "" {
			return fmt.Errorf("clamav.addr must be set when clamav is enabled")
		}
		if c.ClamAV.Timeout <= 0 {
			return fmt.Errorf("clamav.timeout must be positive")
		}
		switch c.ClamAV.Action {
		case "quarantine", "reject":
		default:
			return fmt.Errorf("clamav.action must be quarantine or reject, got %q", c.ClamAV.Action)
		}
	}

	if c.Backup.Enabled {
		if c.Backup.Interval <= 0 {
			return fmt.Errorf("backup.interval must be positive")
		}
		if c.Backup.Keep < 0 {
			return fmt.Errorf("backup.keep must not be negative (0 keeps every snapshot)")
		}
	}

	if c.Alerts.Enabled {
		if c.Alerts.Webhook.URL == "" && len(c.Alerts.Email.To) == 0 {
			return fmt.Errorf("alerts.enabled is on but neither alerts.webhook.url nor " +
				"alerts.email.to is set, so nothing would ever be sent")
		}
		if u := c.Alerts.Webhook.URL; u != "" &&
			!strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("alerts.webhook.url must start with http:// or https://, got %q", u)
		}
		if len(c.Alerts.Email.To) > 0 {
			if c.Alerts.Email.Host == "" {
				return fmt.Errorf("alerts.email.host must be set: the relay the alerts go through, " +
					"which should not be the mail server this instance is watching")
			}
			if c.Alerts.Email.From == "" {
				return fmt.Errorf("alerts.email.from must be set")
			}
			if c.Alerts.Email.Port < 1 || c.Alerts.Email.Port > 65535 {
				return fmt.Errorf("alerts.email.port must be between 1 and 65535")
			}
			switch c.Alerts.Email.TLS {
			case "", "none", "opportunistic", "starttls", "tls":
			default:
				return fmt.Errorf("alerts.email.tls must be one of: none, opportunistic, starttls, tls")
			}
		}
	}

	if c.Outbound.Enabled {
		switch c.Outbound.Mode {
		case "relay":
			if c.Outbound.RelayHost == "" {
				return fmt.Errorf("outbound.relay_host must be set in relay mode: " +
					"the smarthost that actually sends the mail")
			}
			if c.Outbound.RelayPort < 1 || c.Outbound.RelayPort > 65535 {
				return fmt.Errorf("outbound.relay_port must be between 1 and 65535")
			}
		case "direct":

		default:
			return fmt.Errorf("outbound.mode must be relay or direct, got %q", c.Outbound.Mode)
		}
		if c.Outbound.Addr == "" {
			return fmt.Errorf("outbound.addr must be set when outbound submission is enabled")
		}
		if c.Outbound.MaxMessageBytes <= 0 {
			return fmt.Errorf("outbound.max_message_bytes must be positive")
		}
	}

	if c.Webhooks.Enabled {
		if c.Webhooks.Workers <= 0 {
			return fmt.Errorf("webhooks.workers must be positive")
		}
		if c.Webhooks.MaxAttempts <= 0 {
			return fmt.Errorf("webhooks.max_attempts must be positive")
		}
		if c.Webhooks.RetryBase <= 0 || c.Webhooks.RetryMax < c.Webhooks.RetryBase {
			return fmt.Errorf("webhooks.retry_max must be >= webhooks.retry_base, both positive")
		}
		if c.Webhooks.Timeout <= 0 {
			return fmt.Errorf("webhooks.timeout must be positive")
		}
	}

	if c.OIDC.Enabled {
		if c.OIDC.Issuer == "" {
			return fmt.Errorf("oidc.issuer must be set when OIDC is enabled")
		}
		if !strings.HasPrefix(c.OIDC.Issuer, "https://") {
			return fmt.Errorf("oidc.issuer must start with https://, got %q", c.OIDC.Issuer)
		}
		if c.OIDC.ClientID == "" {
			return fmt.Errorf("oidc.client_id must be set when OIDC is enabled")
		}
		if c.OIDC.RedirectURL == "" && c.HTTP.BaseURL == "" {
			return fmt.Errorf("either oidc.redirect_url or http.base_url must be set: " +
				"the provider has to be told exactly where to send the browser back")
		}
		switch c.OIDC.DefaultRole {
		case RoleAdmin, RoleOperator, RoleViewer:
		default:
			return fmt.Errorf("oidc.default_role must be admin, operator or viewer, got %q", c.OIDC.DefaultRole)
		}
		for _, d := range c.OIDC.AllowedDomains {
			if d == "" || strings.ContainsAny(d, "@ ") {
				return fmt.Errorf("oidc.allowed_domains contains %q, which is not a bare domain", d)
			}
		}
	}

	if c.Cluster.Enabled {
		if c.Cluster.Secret == "" {
			return fmt.Errorf("cluster.secret must be set when clustering is enabled: " +
				"the cluster endpoints hand out configuration and must not be open")
		}
		if len(c.Cluster.Secret) < 16 {
			return fmt.Errorf("cluster.secret must be at least 16 characters")
		}
		if c.Cluster.PrimaryNodeID == "" {
			switch c.Cluster.Role {
			case NodePrimary, NodeFollower:
			default:
				return fmt.Errorf("cluster.role must be primary or follower, got %q", c.Cluster.Role)
			}
		}
		if c.Cluster.Interval <= 0 {
			return fmt.Errorf("cluster.interval must be positive")
		}
		if c.Cluster.Timeout <= 0 {
			return fmt.Errorf("cluster.timeout must be positive")
		}
		for _, peer := range c.Cluster.Peers {
			if !strings.HasPrefix(peer, "http://") && !strings.HasPrefix(peer, "https://") {
				return fmt.Errorf("cluster.peers contains %q; peers are URLs, "+
					"for example https://mx2.example.com", peer)
			}
		}
		if c.Cluster.SyncConfig && c.ClusterRole() == NodeFollower && len(c.Cluster.Peers) == 0 {
			return fmt.Errorf("cluster.sync_config is on for a follower with no peers, " +
				"so there is nothing to pull configuration from")
		}
	}
	return nil
}

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	NodePrimary  = "primary"
	NodeFollower = "follower"
)

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) OIDCRedirectURL() string {
	if c.OIDC.RedirectURL != "" {
		return c.OIDC.RedirectURL
	}
	return strings.TrimRight(c.HTTP.BaseURL, "/") + "/api/v1/auth/oidc/callback"
}

func (c *Config) ClusterRole() string {
	if c.Cluster.PrimaryNodeID != "" {
		if strings.EqualFold(c.Cluster.PrimaryNodeID, c.ClusterNodeID()) {
			return NodePrimary
		}
		return NodeFollower
	}
	if c.Cluster.Role == NodePrimary {
		return NodePrimary
	}
	return NodeFollower
}

func (c *Config) ClusterNodeID() string {
	if c.Cluster.NodeID != "" {
		return c.Cluster.NodeID
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "xeronmx"
}

func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "xeronmx.db") }

func (c *Config) SpoolDir() string { return filepath.Join(c.DataDir, "spool") }

func (c *Config) KeyPath() string { return filepath.Join(c.DataDir, "master.key") }

func (c *Config) BackupDir() string {
	if c.Backup.Dir != "" {
		return c.Backup.Dir
	}
	return filepath.Join(c.DataDir, "backups")
}

func (c *Config) ACMECacheDir() string {
	if c.HTTP.ACME.CacheDir != "" {
		return c.HTTP.ACME.CacheDir
	}
	return filepath.Join(c.DataDir, "acme")
}
