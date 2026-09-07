package api

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/clamav"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/dnsbl"
)

func TestSecurityStatus(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(t, "GET", "/api/v1/security/status", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous status, got %d", rec.Code)
	}

	cookie := api.setup(t)

	checker := dnsbl.New(config.DNSBLConfig{
		Enabled: true,
		Zones:   []string{"zen.spamhaus.org"},
	})
	scanner := clamav.New(config.ClamAVConfig{
		Enabled: false,
		Addr:    "localhost:3310",
	})
	api.SetDNSBL(checker)
	api.SetClamAV(scanner)

	rec = api.do(t, "GET", "/api/v1/security/status", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := decodeBody(t, rec)
	dnsblMap, ok := body["dnsbl"].(map[string]any)
	if !ok || dnsblMap["enabled"] != true {
		t.Fatalf("expected dnsbl enabled, got %+v", body["dnsbl"])
	}

	clamavMap, ok := body["clamav"].(map[string]any)
	if !ok || clamavMap["enabled"] != false || clamavMap["status"] != "disabled" {
		t.Fatalf("expected clamav disabled, got %+v", body["clamav"])
	}
}

func TestTestDNSBL(t *testing.T) {
	api := newTestAPI(t)
	cookie := api.setup(t)

	checkerDefault := dnsbl.New(config.DNSBLConfig{
		Enabled: true,
		Zones:   []string{"test.zone.local"},
	})
	api.SetDNSBL(checkerDefault)

	rec := api.do(t, "POST", "/api/v1/security/dnsbl/test", map[string]string{
		"ip": "invalid-ip",
	}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid IP, got %d", rec.Code)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenPacket failed: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			qnameEnd := 12
			for qnameEnd < n && buf[qnameEnd] != 0 {
				qnameEnd += int(buf[qnameEnd]) + 1
			}
			qnameEnd += 5
			if qnameEnd > n {
				continue
			}

			resp := make([]byte, 0, n+16)
			resp = append(resp, buf[0], buf[1])
			resp = append(resp, 0x81, 0x80)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x00)
			resp = append(resp, 0x00, 0x00)
			resp = append(resp, buf[12:qnameEnd]...)
			resp = append(resp, 0xc0, 0x0c)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x01)
			resp = append(resp, 0x00, 0x00, 0x01, 0x2c)
			resp = append(resp, 0x00, 0x04)
			resp = append(resp, 127, 0, 0, 2)

			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	mockResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}

	checker := dnsbl.New(config.DNSBLConfig{
		Enabled: true,
		Zones:   []string{"test.zone.local"},
		Timeout: 2 * time.Second,
	}, mockResolver)
	api.SetDNSBL(checker)

	rec = api.do(t, "POST", "/api/v1/security/dnsbl/test", map[string]string{
		"ip": "198.51.100.2",
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := decodeBody(t, rec)
	if body["listed"] != true {
		t.Fatalf("expected listed = true, got %+v", body)
	}
	if body["zone"] != "test.zone.local" {
		t.Fatalf("expected zone test.zone.local, got %v", body["zone"])
	}
}
