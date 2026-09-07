package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

func newManager(t *testing.T, domains ...string) *Manager {
	t.Helper()
	if len(domains) == 0 {
		domains = []string{"mx2.test.example"}
	}
	m, err := New(
		config.ACMEConfig{Enabled: true, Domains: domains, TermsAgreed: true},
		t.TempDir(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func handshake(t *testing.T, cfg *tls.Config, serverName string) (*x509.Certificate, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	deadline := time.Now().Add(10 * time.Second)
	clientConn.SetDeadline(deadline)
	serverConn.SetDeadline(deadline)

	errc := make(chan error, 1)
	go func() {
		server := tls.Server(serverConn, cfg)
		errc <- server.Handshake()
	}()

	client := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err := client.Handshake(); err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	return client.ConnectionState().PeerCertificates[0], nil
}

func TestSTARTTLSWorksBeforeTheFirstCertificate(t *testing.T) {
	m := newManager(t)

	leaf, err := handshake(t, m.SMTPTLSConfig(), "mx2.test.example")
	if err != nil {
		t.Fatalf("the handshake failed with no CA certificate available: %v", err)
	}
	if leaf.Subject.CommonName != "mx2.test.example" {
		t.Errorf("certificate is for %q, want mx2.test.example", leaf.Subject.CommonName)
	}
}

func TestHandshakeWithoutSNI(t *testing.T) {
	m := newManager(t)
	if _, err := handshake(t, m.SMTPTLSConfig(), ""); err != nil {
		t.Fatalf("handshake without SNI failed: %v", err)
	}
}

func TestAdminPanelIsReachableBeforeTheFirstCertificate(t *testing.T) {
	m := newManager(t)
	if _, err := handshake(t, m.TLSConfig(), "mx2.test.example"); err != nil {
		t.Fatalf("the panel could not complete a handshake: %v", err)
	}
}

func TestInterimCertificateCoversEveryConfiguredDomain(t *testing.T) {
	m := newManager(t, "mx2.test.example", "mx3.test.example")

	for _, name := range []string{"mx2.test.example", "mx3.test.example"} {
		leaf, err := handshake(t, m.TLSConfig(), name)
		if err != nil {
			t.Fatalf("handshake for %s failed: %v", name, err)
		}
		if err := leaf.VerifyHostname(name); err != nil {
			t.Errorf("interim certificate does not cover %s: %v", name, err)
		}
	}
}

func TestStateStartsSelfSignedAndFlipsOnAdopt(t *testing.T) {
	m := newManager(t)

	st := m.CertificateState()
	if st.Source != SourceSelfSigned {
		t.Fatalf("source is %q on a fresh manager, want %q", st.Source, SourceSelfSigned)
	}
	if st.Domain != "mx2.test.example" {
		t.Errorf("domain is %q", st.Domain)
	}

	real, err := selfSigned([]string{"mx2.test.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.adopt(real) {
		t.Error("adopt reported no change on the first certificate")
	}
	if st = m.CertificateState(); st.Source != SourceACME {
		t.Fatalf("source is %q after adopting, want %q", st.Source, SourceACME)
	}
	if m.adopt(real) {
		t.Error("adopt reported a change for an identical certificate; the renewal log would repeat every refresh")
	}
}

func TestIssuedCertificateSupersedesTheInterimOne(t *testing.T) {
	m := newManager(t)

	interim, err := handshake(t, m.TLSConfig(), "mx2.test.example")
	if err != nil {
		t.Fatal(err)
	}

	real, err := selfSigned([]string{"mx2.test.example"})
	if err != nil {
		t.Fatal(err)
	}
	m.adopt(real)

	served, err := handshake(t, m.TLSConfig(), "mx2.test.example")
	if err != nil {
		t.Fatal(err)
	}
	if served.SerialNumber.Cmp(interim.SerialNumber) == 0 {
		t.Fatal("the interim certificate is still being served after a real one was adopted")
	}
	if served.SerialNumber.Cmp(real.Leaf.SerialNumber) != 0 {
		t.Fatal("the served certificate is not the adopted one")
	}
}

func TestFailureIsRecordedInState(t *testing.T) {
	m := newManager(t)
	m.recordFailure(io.ErrUnexpectedEOF)

	st := m.CertificateState()
	if st.LastError == "" {
		t.Fatal("a failed attempt left no last_error for the operator to see")
	}
	if st.Source != SourceSelfSigned {
		t.Errorf("source is %q after a failure, want %q", st.Source, SourceSelfSigned)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	m := newManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestNewRejectsNoDomains(t *testing.T) {
	_, err := New(config.ACMEConfig{Enabled: true}, t.TempDir(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("New accepted a configuration with no domains")
	}
}

func TestHostPolicyIgnoresThePort(t *testing.T) {
	policy := hostPolicy([]string{"mx2.example.com", "mail.example.com"})
	ctx := context.Background()

	for _, host := range []string{
		"mx2.example.com",
		"mx2.example.com:80",
		"mx2.example.com:8080",
		"mail.example.com:443",
	} {
		if err := policy(ctx, host); err != nil {
			t.Errorf("a configured name was refused as %q: %v", host, err)
		}
	}

	for _, host := range []string{
		"evil.example.com",
		"evil.example.com:80",
		"",
		":80",
	} {
		if err := policy(ctx, host); err == nil {
			t.Errorf("SECURITY: %q was accepted; a certificate could be requested for it", host)
		}
	}
}

func TestChallengeHandlerExistsBeforeTheListenerRuns(t *testing.T) {
	m := newManager(t, "mx2.example.com")

	if m.challengeHandler == nil {
		t.Fatal("the HTTP-01 handler is not registered by New")
	}

	req := httptest.NewRequest(http.MethodGet,
		"http://mx2.example.com/.well-known/acme-challenge/sometoken", nil)
	req.Host = "mx2.example.com"
	rec := httptest.NewRecorder()
	m.challengeHandler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("a configured host was refused by the handler (status %d)", rec.Code)
	}
	if rec.Code != http.StatusNotFound {
		t.Logf("unknown token answered %d", rec.Code)
	}
}

func TestIncompatibleCAIsRecognised(t *testing.T) {
	if !incompatibleCA(errors.New(`Post "": unsupported protocol scheme ""`)) {
		t.Error("the finalize-without-Location failure is not recognised")
	}
	for _, other := range []error{
		nil,
		errors.New("acme/autocert: unable to satisfy \"x\" for domain \"y\": no viable challenge type found"),
		errors.New(`Post "https://acme-v02.api.letsencrypt.org/acme/new-order": dial tcp: i/o timeout`),
		errors.New("429 urn:ietf:params:acme:error:rateLimited"),
	} {
		if incompatibleCA(other) {
			t.Errorf("an ordinary failure was reported as a CA incompatibility: %v", other)
		}
	}
}

func TestIssuanceGuardBoundsARunaway(t *testing.T) {
	g := newIssuanceGuard(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	start := time.Now()

	for i := 0; i < guardBurst; i++ {
		if wait := g.take(start); wait != 0 {
			t.Fatalf("request %d was delayed by %v inside the burst", i, wait)
		}
	}

	for i := 0; i < 50; i++ {
		if wait := g.take(start); wait <= 0 {
			t.Fatalf("request %d past the burst was let through immediately", i)
		}
	}

	allowed := 0
	for elapsed := time.Duration(0); elapsed < time.Hour; elapsed += time.Second {
		if g.take(start.Add(elapsed)) == 0 {
			allowed++
		}
	}
	if allowed > 40 {
		t.Fatalf("%d requests reached the CA in an hour of runaway renewal", allowed)
	}
	if allowed == 0 {
		t.Fatal("nothing got through at all; a real renewal would never happen")
	}
}

func TestIssuanceGuardRefills(t *testing.T) {
	g := newIssuanceGuard(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	start := time.Now()

	for i := 0; i < guardBurst; i++ {
		g.take(start)
	}
	if wait := g.take(start); wait == 0 {
		t.Fatal("the burst was not exhausted")
	}

	later := start.Add(10 * guardRefill)
	for i := 0; i < 10; i++ {
		if wait := g.take(later); wait != 0 {
			t.Fatalf("token %d was not refilled after waiting: %v", i, wait)
		}
	}
	if wait := g.take(later); wait == 0 {
		t.Fatal("more tokens were handed out than had been earned")
	}
}

func TestIssuanceGuardIsInvisibleInNormalUse(t *testing.T) {
	g := newIssuanceGuard(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now()

	for renewal := 0; renewal < 12; renewal++ {
		for req := 0; req < 15; req++ {
			if wait := g.take(now); wait != 0 {
				t.Fatalf("renewal %d, request %d was delayed by %v", renewal, req, wait)
			}
		}
		now = now.Add(60 * 24 * time.Hour)
	}
}

func TestRenewBeforeIsConfigurable(t *testing.T) {
	m, err := New(
		config.ACMEConfig{
			Enabled: true, Domains: []string{"mx2.test.example"}, TermsAgreed: true,
			RenewBefore: 36 * time.Hour,
		},
		t.TempDir(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if m.mgr.RenewBefore != 36*time.Hour {
		t.Fatalf("RenewBefore = %v, want the configured value", m.mgr.RenewBefore)
	}

	m = newManager(t)
	if m.mgr.RenewBefore != defaultRenewBefore {
		t.Fatalf("RenewBefore = %v with nothing configured, want the default", m.mgr.RenewBefore)
	}
}
