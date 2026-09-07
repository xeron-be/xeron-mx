package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/xeron-be/xeron-mx/internal/config"
)

const (
	SourceACME       = "acme"
	SourceSelfSigned = "self-signed"
)

const (
	retryInitial       = 5 * time.Minute
	retryMax           = time.Hour
	refreshInterval    = 6 * time.Hour
	obtainTimeout      = 90 * time.Second
	selfSignedLifetime = 397 * 24 * time.Hour

	defaultRenewBefore = 30 * 24 * time.Hour
)

type Manager struct {
	mgr       *autocert.Manager
	log       *slog.Logger
	domains   []string
	primary   string
	challenge string

	challengeHandler http.Handler

	mu       sync.RWMutex
	issued   *tls.Certificate
	fallback *tls.Certificate
	source   string
	since    time.Time
	lastErr  string
}

type State struct {
	Source    string
	Domain    string
	Since     time.Time
	LastError string
}

func New(cfg config.ACMEConfig, cacheDir string, log *slog.Logger) (*Manager, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("acme: no domains configured")
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("acme: create cache dir: %w", err)
	}

	domains := make([]string, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(d)))
	}

	renewBefore := cfg.RenewBefore
	if renewBefore <= 0 {
		renewBefore = defaultRenewBefore
	}

	am := &autocert.Manager{
		Cache: autocert.DirCache(cacheDir),

		HostPolicy: hostPolicy(domains),
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.Email,

		RenewBefore: renewBefore,
	}

	am.Client = &acme.Client{
		HTTPClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: newIssuanceGuard(nil, log),
		},
	}
	if cfg.DirectoryURL != "" {
		am.Client.DirectoryURL = cfg.DirectoryURL
		log.Warn("using a non-default ACME directory", "url", cfg.DirectoryURL)
	}

	fallback, err := selfSigned(domains)
	if err != nil {
		return nil, fmt.Errorf("acme: generate the interim certificate: %w", err)
	}

	return &Manager{
		mgr:       am,
		log:       log,
		domains:   domains,
		primary:   domains[0],
		challenge: cfg.ChallengeAddr,
		fallback:  fallback,
		source:    SourceSelfSigned,
		since:     time.Now(),

		challengeHandler: am.HTTPHandler(nil),
	}, nil
}

func hostPolicy(domains []string) autocert.HostPolicy {
	allow := autocert.HostWhitelist(domains...)
	return func(ctx context.Context, host string) error {
		if bare, _, err := net.SplitHostPort(host); err == nil {
			host = bare
		}
		return allow(ctx, host)
	}
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: m.getCertificate,
	}
}

func (m *Manager) SMTPTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.getCertificate,
	}
}

func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		return m.mgr.GetCertificate(hello)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.issued != nil {
		return m.issued, nil
	}
	return m.fallback, nil
}

func (m *Manager) CertificateState() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return State{
		Source:    m.source,
		Domain:    m.primary,
		Since:     m.since,
		LastError: m.lastErr,
	}
}

func (m *Manager) Run(ctx context.Context) {
	delay := retryInitial
	warned := false

	for {
		cert, err := m.obtain(ctx)
		if err == nil {
			if m.adopt(cert) {
				if warned {
					m.log.Info("certificate obtained; the interim self-signed certificate is no longer served",
						"domain", m.primary)
				} else {
					m.log.Info("certificate ready", "domain", m.primary)
				}
			}
			warned = false
			delay = retryInitial
			if !sleep(ctx, refreshInterval) {
				return
			}
			continue
		}

		m.recordFailure(err)
		if warned {
			m.log.Warn("still no certificate, retrying",
				"domain", m.primary, "error", err, "next_attempt_in", delay.String())
		} else {
			m.log.Warn("no certificate yet: serving a self-signed one meanwhile, and retrying",
				"domain", m.primary, "error", err,
				"challenge_addr", m.challenge,
				"check", "port 80 must be reachable from the internet by name for the HTTP-01 challenge, and under Docker it must also be published",
				"impact", "the admin panel and STARTTLS keep working, but the certificate is not one a client can verify")
			warned = true
		}
		if incompatibleCA(err) {
			m.log.Error("this ACME server is not one the client can finish an order with",
				"domain", m.primary,
				"why", "the CA answered the finalize request without a Location header. "+
					"RFC 8555 does not require one, but golang.org/x/crypto/acme reads the "+
					"order's URL from it, so the order cannot be polled and the certificate "+
					"is never collected",
				"cost", "the CA has already issued a certificate by this point, and every retry "+
					"issues another one, which will run into its rate limits",
				"do", "use Let's Encrypt, which sends that header, or another CA that does; "+
					"this is not something the configuration can work around")
		}

		if !sleep(ctx, delay) {
			return
		}
		delay = min(delay*2, retryMax)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (m *Manager) obtain(ctx context.Context) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, obtainTimeout)
	defer cancel()

	done := make(chan struct{})
	var (
		cert *tls.Certificate
		err  error
	)
	go func() {
		defer close(done)
		cert, err = m.mgr.GetCertificate(&tls.ClientHelloInfo{
			ServerName:   m.primary,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},

			SupportedCurves:  []tls.CurveID{tls.CurveP256},
			SupportedPoints:  []uint8{0},
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PKCS1WithSHA256},
		})
	}()

	select {
	case <-done:
		return cert, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Manager) adopt(cert *tls.Certificate) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := m.issued == nil || !slices.EqualFunc(m.issued.Certificate, cert.Certificate, slices.Equal)
	if m.issued == nil {
		m.since = time.Now()
	}
	m.issued = cert
	m.source = SourceACME
	m.lastErr = ""
	return changed
}

func (m *Manager) recordFailure(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = err.Error()
}

func (m *Manager) RunChallengeServer(ctx context.Context) error {
	addr := m.challenge
	if addr == "" {
		addr = ":80"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           m.challengeHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {

		return fmt.Errorf("acme: cannot listen on %s for the HTTP-01 challenge "+
			"(this port must be free and reachable from the internet): %w", addr, err)
	}
	m.log.Info("acme challenge listener started", "addr", addr, "domains", m.primary)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("acme: challenge server: %w", err)
	}
	return nil
}

func incompatibleCA(err error) bool {
	return err != nil && strings.Contains(err.Error(), `Post "": unsupported protocol scheme`)
}

func selfSigned(domains []string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domains[0],
			Organization: []string{"XeronMX interim certificate"},
		},
		DNSNames:              domains,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
