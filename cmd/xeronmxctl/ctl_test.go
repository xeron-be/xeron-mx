package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/acme"
	"github.com/xeron-be/xeron-mx/internal/api"
	"github.com/xeron-be/xeron-mx/internal/auth"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/cluster"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/version"
	"github.com/xeron-be/xeron-mx/internal/webhook"
)

func runArgs(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	oldArgs := os.Args
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	jsonOut = false

	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}

	defer func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		jsonOut = false
		rOut.Close()
		rErr.Close()
	}()

	os.Args = append([]string{"xeronmxctl"}, args...)
	os.Stdout = wOut
	os.Stderr = wErr

	var bufOut, bufErr bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(&bufOut, rOut)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&bufErr, rErr)
	}()

	runErr := run()

	wOut.Close()
	wErr.Close()
	wg.Wait()

	return bufOut.String(), bufErr.String(), runErr
}

type testEnv struct {
	server  *api.Server
	ts      *httptest.Server
	db      *store.DB
	token   string
	adminID int64
}

type mockCertReporter struct{}

func (mockCertReporter) CertificateState() acme.State {
	return acme.State{
		Source:    "self-signed",
		Domain:    "mx.test.example",
		Since:     time.Now().UTC(),
		LastError: "acme challenge refused",
	}
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	blobs, err := blob.Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("blob.Open: %v", err)
	}

	cfg := config.Default()
	cfg.SMTP.Hostname = "mx.test.example"
	cfg.Webhooks.Enabled = true
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	collector := metrics.New(db, &metrics.Counters{}, "", log)

	s := api.New(cfg.HTTP, cfg.SMTP, cfg.Queue, db, blobs, log, collector)

	m := maintenance.NewManager(false)
	s.SetMaintenance(m)

	whDispatcher := webhook.New(cfg.Webhooks, db, blobs, "mx.test.example", log)
	s.SetWebhooks(whDispatcher)

	s.SetCertificateReporter(mockCertReporter{})

	pwHash, _ := auth.HashPassword("secretpass123")
	adminID, err := db.CreateUser(context.Background(), "admin@test.example", pwHash, store.RoleAdmin)
	if err != nil {
		t.Fatalf("db.CreateUser: %v", err)
	}

	rawTok, tokHash, prefix, err := auth.NewAPIToken()
	if err != nil {
		t.Fatalf("auth.NewAPIToken: %v", err)
	}
	tokRec := &store.APIToken{
		Name: "test-token", Prefix: prefix, Role: store.RoleAdmin, CreatedBy: &adminID,
	}
	_, err = db.CreateAPIToken(context.Background(), tokRec, tokHash)
	if err != nil {
		t.Fatalf("db.CreateAPIToken: %v", err)
	}

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	return &testEnv{
		server:  s,
		ts:      ts,
		db:      db,
		token:   rawTok,
		adminID: adminID,
	}
}

func TestOutputHelpers(t *testing.T) {
	if ago(nil) != "never" {
		t.Fatalf("expected never, got %s", ago(nil))
	}
	var zero time.Time
	if ago(&zero) != "never" {
		t.Fatalf("expected never, got %s", ago(&zero))
	}
	pastSec := time.Now().Add(-30 * time.Second)
	if ago(&pastSec) != "30s ago" {
		t.Fatalf("unexpected ago: %s", ago(&pastSec))
	}
	pastMin := time.Now().Add(-10 * time.Minute)
	if ago(&pastMin) != "10m ago" {
		t.Fatalf("unexpected ago: %s", ago(&pastMin))
	}
	pastHour := time.Now().Add(-5 * time.Hour)
	if ago(&pastHour) != "5h ago" {
		t.Fatalf("unexpected ago: %s", ago(&pastHour))
	}
	pastDays := time.Now().Add(-72 * time.Hour)
	if ago(&pastDays) != "3d ago" {
		t.Fatalf("unexpected ago: %s", ago(&pastDays))
	}
	future := time.Now().Add(10 * time.Minute)
	if ago(&future) != "in 10m" {
		t.Fatalf("unexpected future ago: %s", ago(&future))
	}

	if until(nil) != "never" {
		t.Fatalf("expected never, got %s", until(nil))
	}
	if until(&zero) != "never" {
		t.Fatalf("expected never, got %s", until(&zero))
	}
	if until(&pastSec) != "expired" {
		t.Fatalf("expected expired, got %s", until(&pastSec))
	}
	if until(&future) != "in 10m" {
		t.Fatalf("unexpected until: %s", until(&future))
	}

	if short(10*time.Second) != "10s" {
		t.Fatalf("unexpected short seconds: %s", short(10*time.Second))
	}
	if short(15*time.Minute) != "15m" {
		t.Fatalf("unexpected short minutes: %s", short(15*time.Minute))
	}
	if short(12*time.Hour) != "12h" {
		t.Fatalf("unexpected short hours: %s", short(12*time.Hour))
	}
	if short(96*time.Hour) != "4d" {
		t.Fatalf("unexpected short days: %s", short(96*time.Hour))
	}

	if bytesHuman(500) != "500 B" {
		t.Fatalf("unexpected bytesHuman: %s", bytesHuman(500))
	}
	if bytesHuman(1024) != "1.0 KB" {
		t.Fatalf("unexpected bytesHuman: %s", bytesHuman(1024))
	}
	if bytesHuman(5*1024*1024) != "5.0 MB" {
		t.Fatalf("unexpected bytesHuman: %s", bytesHuman(5*1024*1024))
	}
	if bytesHuman(10*1024*1024*1024) != "10.0 GB" {
		t.Fatalf("unexpected bytesHuman: %s", bytesHuman(10*1024*1024*1024))
	}

	if yesNo(true) != "yes" || yesNo(false) != "no" {
		t.Fatalf("unexpected yesNo output")
	}

	if truncate("hello", 10) != "hello" {
		t.Fatalf("unexpected truncate: %s", truncate("hello", 10))
	}
	if truncate("hello", 5) != "hello" {
		t.Fatalf("unexpected truncate: %s", truncate("hello", 5))
	}
	if truncate("hello world", 6) != "hello…" {
		t.Fatalf("unexpected truncate: %s", truncate("hello world", 6))
	}
	if truncate("hello", 1) != "h" {
		t.Fatalf("unexpected truncate: %s", truncate("hello", 1))
	}
	if truncate("hello", 0) != "" {
		t.Fatalf("unexpected truncate: %s", truncate("hello", 0))
	}

	var buf bytes.Buffer
	if err := writeOut(&buf, []byte("test")); err != nil || buf.String() != "test" {
		t.Fatalf("writeOut failed: %v", err)
	}

	tbl := newTable("H1", "H2")
	tbl.row("R1", "R2")
	tbl.flush()

	note("test note %d", 1)
	warn("test warn %s", "err")

	if summarise(nil) != "" {
		t.Fatalf("expected empty summarise")
	}
	s := summarise(map[string]any{"b": 2, "a": 1})
	if s != "a=1 b=2" {
		t.Fatalf("unexpected summarise: %s", s)
	}

	first, rest := split([]string{}, "def")
	if first != "def" || len(rest) != 0 {
		t.Fatalf("unexpected split fallback")
	}
	first, rest = split([]string{"a", "b", "c"}, "def")
	if first != "a" || len(rest) != 2 || rest[0] != "b" || rest[1] != "c" {
		t.Fatalf("unexpected split result")
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	p := fs.Int("port", 0, "")
	parsedArgs, err := parseMixed(fs, []string{"alpha", "-port=8080", "beta"})
	if err != nil {
		t.Fatalf("parseMixed error: %v", err)
	}
	if *p != 8080 || len(parsedArgs) != 2 || parsedArgs[0] != "alpha" || parsedArgs[1] != "beta" {
		t.Fatalf("unexpected parseMixed result: %d, %v", *p, parsedArgs)
	}
}

func TestClientBasicsAndErrors(t *testing.T) {
	apiErr := &APIError{Status: 404, Message: "item not found"}
	if apiErr.Error() != "item not found" {
		t.Fatalf("unexpected APIError: %s", apiErr.Error())
	}
	apiErrNoMsg := &APIError{Status: 500}
	if apiErrNoMsg.Error() != "the server answered 500" {
		t.Fatalf("unexpected APIError: %s", apiErrNoMsg.Error())
	}

	if _, err := NewClient(Settings{}); err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Fatalf("expected no server URL error, got %v", err)
	}
	if _, err := NewClient(Settings{URL: "bad:url"}); err == nil || !strings.Contains(err.Error(), "is not a URL") {
		t.Fatalf("expected invalid URL error, got %v", err)
	}
	if _, err := NewClient(Settings{URL: "ftp://example.com", Token: "tok"}); err == nil || !strings.Contains(err.Error(), "http:// or https://") {
		t.Fatalf("expected scheme error, got %v", err)
	}
	if _, err := NewClient(Settings{URL: "http://example.com"}); err == nil || !strings.Contains(err.Error(), "no API token") {
		t.Fatalf("expected no token error, got %v", err)
	}

	c, err := NewClient(Settings{URL: "https://example.com/", Token: "secret", Insecure: true})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if c.base != "https://example.com" || c.token != "secret" {
		t.Fatalf("unexpected client state: %+v", c)
	}
}

func TestClientMethodsMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"foo": "bar"})
	})
	mux.HandleFunc("GET /raw", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("raw-bytes-content"))
	})
	mux.HandleFunc("GET /bad-json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json"))
	})
	mux.HandleFunc("GET /err-json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "custom validation failed"})
	})
	mux.HandleFunc("GET /err-text", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal crash"))
	})
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("PATCH /echo", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("DELETE /del", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST /raw-post", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/yaml" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(map[string]string{"got": string(raw)})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewClient(Settings{URL: srv.URL, Token: "mock-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()

	var gotJSON map[string]string
	if err := c.get(ctx, "/json", &gotJSON); err != nil || gotJSON["foo"] != "bar" {
		t.Fatalf("get json failed: %v, %v", err, gotJSON)
	}

	var gotRaw []byte
	if err := c.get(ctx, "/raw", &gotRaw); err != nil || string(gotRaw) != "raw-bytes-content" {
		t.Fatalf("get raw failed: %v, %s", err, string(gotRaw))
	}

	var badJSONTarget map[string]string
	if err := c.get(ctx, "/bad-json", &badJSONTarget); err == nil {
		t.Fatalf("expected unmarshal error on bad json")
	}

	var errTarget map[string]any
	err = c.get(ctx, "/err-json", &errTarget)
	if err == nil {
		t.Fatalf("expected error from /err-json")
	}
	var aErr *APIError
	if !errors.As(err, &aErr) || aErr.Status != 400 || aErr.Message != "custom validation failed" {
		t.Fatalf("unexpected APIError: %v", err)
	}

	err = c.get(ctx, "/err-text", &errTarget)
	if err == nil {
		t.Fatalf("expected error from /err-text")
	}
	if !errors.As(err, &aErr) || aErr.Status != 500 || aErr.Message != "internal crash" {
		t.Fatalf("unexpected APIError for text: %v", err)
	}

	var postEcho map[string]any
	if err := c.post(ctx, "/echo", map[string]any{"val": 123}, &postEcho); err != nil || postEcho["val"].(float64) != 123 {
		t.Fatalf("post echo failed: %v, %v", err, postEcho)
	}

	var patchEcho map[string]any
	if err := c.patch(ctx, "/echo", map[string]any{"patch": true}, &patchEcho); err != nil || patchEcho["patch"].(bool) != true {
		t.Fatalf("patch echo failed: %v, %v", err, patchEcho)
	}

	var delResp map[string]bool
	if err := c.delete(ctx, "/del", &delResp); err != nil || !delResp["deleted"] {
		t.Fatalf("delete failed: %v, %v", err, delResp)
	}

	var rawPostResp map[string]string
	if err := c.postRaw(ctx, "/raw-post", "application/yaml", []byte("yaml-body"), &rawPostResp); err != nil || rawPostResp["got"] != "yaml-body" {
		t.Fatalf("postRaw failed: %v, %v", err, rawPostResp)
	}
}

func TestSettingsSaveLoadAndOverrides(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("AppData", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("XERONMX_URL", "")
	t.Setenv("XERONMX_TOKEN", "")

	p, err := ConfigPath()
	if err != nil || !strings.HasSuffix(p, filepath.Join("xeronmx", "cli.yaml")) {
		t.Fatalf("unexpected ConfigPath: %v, %s", err, p)
	}

	savedPath, err := SaveSettings(Settings{URL: "http://saved.example", Token: "saved-token", Insecure: true})
	if err != nil {
		t.Fatalf("SaveSettings failed: %v", err)
	}
	warnIfReadable(savedPath)

	loaded, err := LoadSettings(Settings{})
	if err != nil {
		t.Fatalf("LoadSettings failed: %v", err)
	}
	if loaded.URL != "http://saved.example" || loaded.Token != "saved-token" || !loaded.Insecure {
		t.Fatalf("unexpected loaded settings: %+v", loaded)
	}

	t.Setenv("XERONMX_URL", "http://env.example")
	t.Setenv("XERONMX_TOKEN", "env-token")
	loadedEnv, err := LoadSettings(Settings{})
	if err != nil {
		t.Fatalf("LoadSettings env: %v", err)
	}
	if loadedEnv.URL != "http://env.example" || loadedEnv.Token != "env-token" {
		t.Fatalf("unexpected env settings: %+v", loadedEnv)
	}

	loadedFlags, err := LoadSettings(Settings{URL: "http://flag.example", Token: "flag-token", Insecure: true})
	if err != nil {
		t.Fatalf("LoadSettings flags: %v", err)
	}
	if loadedFlags.URL != "http://flag.example" || loadedFlags.Token != "flag-token" || !loadedFlags.Insecure {
		t.Fatalf("unexpected flag settings: %+v", loadedFlags)
	}
}

func TestCLIBasics(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("AppData", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("XERONMX_URL", "")
	t.Setenv("XERONMX_TOKEN", "")

	_, _, err := runArgs(t)
	if err == nil || !strings.Contains(err.Error(), "no command given") {
		t.Fatalf("expected no command given, got %v", err)
	}

	_, _, err = runArgs(t, "-invalid-flag-999")
	if err == nil {
		t.Fatalf("expected flag parse error")
	}

	out, _, err := runArgs(t, "help")
	if err != nil || !strings.Contains(out, "xeronmxctl [flags] <command>") {
		t.Fatalf("help failed: %v, %s", err, out)
	}

	for _, h := range []string{"-h", "--help"} {
		_, _, err := runArgs(t, h)
		if !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("expected flag.ErrHelp, got %v", err)
		}
	}

	_, _, err = runArgs(t, "boguscmd")
	if err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Fatalf("expected no server URL error, got %v", err)
	}

	_, _, err = runArgs(t, "--url", "http://localhost:8080", "--token", "testtok", "boguscmd")
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

func TestCLIVersionAndLogin(t *testing.T) {
	env := setupTestEnv(t)
	tempDir := t.TempDir()
	t.Setenv("AppData", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("XERONMX_URL", "")
	t.Setenv("XERONMX_TOKEN", "")

	out, _, err := runArgs(t, "version")
	if err != nil || !strings.Contains(out, "xeronmxctl "+version.String()) {
		t.Fatalf("version without url failed: %v, %s", err, out)
	}

	out, _, err = runArgs(t, "--url", env.ts.URL, "--token", env.token, "version")
	if err != nil || !strings.Contains(out, "server") {
		t.Fatalf("version with url failed: %v, %s", err, out)
	}

	_, _, err = runArgs(t, "login")
	if err == nil || !strings.Contains(err.Error(), "login needs --url and --token") {
		t.Fatalf("expected missing args error for login, got %v", err)
	}

	_, _, err = runArgs(t, "login", "--url", env.ts.URL, "--token", "invalid-token-here")
	if err == nil || !strings.Contains(err.Error(), "the server did not accept that token") {
		t.Fatalf("expected token refusal error, got %v", err)
	}

	out, _, err = runArgs(t, "login", "--url", env.ts.URL, "--token", env.token, "--insecure")
	if err != nil || !strings.Contains(out, "Signed in to") {
		t.Fatalf("login success failed: %v, %s", err, out)
	}
}

func TestCLIFullE2EWorkflow(t *testing.T) {
	env := setupTestEnv(t)
	tempDir := t.TempDir()
	t.Setenv("AppData", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("XERONMX_URL", env.ts.URL)
	t.Setenv("XERONMX_TOKEN", env.token)

	baseFlags := []string{"--url", env.ts.URL, "--token", env.token}

	t.Run("status_empty", func(t *testing.T) {
		out, _, err := runArgs(t, append(baseFlags, "status")...)
		if err != nil || !strings.Contains(out, "XeronMX") || !strings.Contains(out, "tls") {
			t.Fatalf("status empty failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "status")...)
		if err != nil || !strings.Contains(outJSON, `"version"`) {
			t.Fatalf("status --json failed: %v, %s", err, outJSON)
		}
	})

	t.Run("domains", func(t *testing.T) {
		out, _, err := runArgs(t, append(baseFlags, "domains", "list")...)
		if err != nil || !strings.Contains(out, "No domains configured") {
			t.Fatalf("domains list empty failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "domains", "add")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl domains add") {
			t.Fatalf("expected usage error for domains add, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "domains", "add", "example.com", "mail.example.com", "--port", "25", "--tls", "starttls", "--retention-hours", "48")...)
		if err != nil || !strings.Contains(out, "Added example.com") {
			t.Fatalf("domains add failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "domains", "add", "example2.com", "mail2.example.com")...)
		if err != nil || !strings.Contains(outJSON, `"example2.com"`) {
			t.Fatalf("domains add --json failed: %v, %s", err, outJSON)
		}

		out, _, err = runArgs(t, append(baseFlags, "domains", "list")...)
		if err != nil || !strings.Contains(out, "example.com") {
			t.Fatalf("domains list populated failed: %v, %s", err, out)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "domains", "list")...)
		if err != nil || !strings.Contains(outJSON, `"example.com"`) {
			t.Fatalf("domains list --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "domains", "test")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl domains test") {
			t.Fatalf("expected usage error for domains test, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "domains", "test", "1")...)
		if err != nil {
			t.Fatalf("domains test probe returned error: %v", err)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "domains", "test", "1")...)
		if err != nil || !strings.Contains(outJSON, `"took_ms"`) {
			t.Fatalf("domains test --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "domains", "rm")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl domains rm") {
			t.Fatalf("expected usage error for domains rm, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "domains", "rm", "2")...)
		if err != nil || !strings.Contains(out, "Deleted") {
			t.Fatalf("domains rm failed: %v, %s", err, out)
		}

		out, _, err = runArgs(t, append(baseFlags, "domains", "rm", "1", "--force")...)
		if err != nil || !strings.Contains(out, "Deleted") {
			t.Fatalf("domains rm force failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "domains", "bogus")...)
		if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
			t.Fatalf("expected unknown subcommand error, got %v", err)
		}
	})

	t.Run("domains_rm_conflict", func(t *testing.T) {
		domID, err := env.db.CreateDomain(context.Background(), &store.Domain{
			Name: "conflict.example", PrimaryHost: "127.0.0.1", PrimaryPort: 25, PrimaryTLS: "none", RetentionHours: 24, Enabled: true,
		})
		if err != nil {
			t.Fatalf("create domain: %v", err)
		}
		msg := &store.Message{
			ID: "msg-conflict-1", DomainID: domID, Direction: store.DirectionInbound,
			EnvelopeFrom: "sender@conflict.example", EnvelopeTo: []string{"rcpt@conflict.example"},
			Subject: "Conflict Mail", SizeBytes: 500, ReceivedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour), Status: store.StatusQueued,
		}
		if err := env.db.Enqueue(context.Background(), msg); err != nil {
			t.Fatalf("enqueue message: %v", err)
		}

		domIDStr := fmt.Sprintf("%d", domID)
		_, _, err = runArgs(t, append(baseFlags, "domains", "rm", domIDStr)...)
		if err == nil || !strings.Contains(err.Error(), "pass --force to delete it and the mail with it") {
			t.Fatalf("expected 409 conflict error on domain rm with queued mail, got %v", err)
		}

		out, _, err := runArgs(t, append(baseFlags, "domains", "rm", domIDStr, "--force")...)
		if err != nil || !strings.Contains(out, "Deleted") {
			t.Fatalf("domain rm force failed: %v, %s", err, out)
		}
	})

	t.Run("status_populated", func(t *testing.T) {
		domID, err := env.db.CreateDomain(context.Background(), &store.Domain{
			Name: "statuscheck.example", PrimaryHost: "127.0.0.1", PrimaryPort: 25, PrimaryTLS: "none", RetentionHours: 24, Enabled: true,
		})
		if err != nil {
			t.Fatalf("create domain: %v", err)
		}
		env.db.RecordProbe(context.Background(), domID, false, "connection refused", 0, 1, time.Now().UTC())

		out, _, err := runArgs(t, append(baseFlags, "status")...)
		if err != nil || !strings.Contains(out, "statuscheck.example") || !strings.Contains(out, "At least one primary is down") {
			t.Fatalf("status with down primary failed: %v, %s", err, out)
		}
		env.db.DeleteDomain(context.Background(), domID)
	})

	t.Run("queue", func(t *testing.T) {
		domID, err := env.db.CreateDomain(context.Background(), &store.Domain{
			Name: "queuedom.example", PrimaryHost: "127.0.0.1", PrimaryPort: 25, PrimaryTLS: "none", RetentionHours: 24, Enabled: true,
		})
		if err != nil {
			t.Fatalf("create domain: %v", err)
		}

		msg := &store.Message{
			ID: "msg-queue-test-1", DomainID: domID, Direction: store.DirectionInbound,
			EnvelopeFrom: "alice@queuedom.example", EnvelopeTo: []string{"bob@queuedom.example"},
			Subject: "Hello Queue", SizeBytes: 1024, ReceivedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour), Status: store.StatusQueued,
		}
		if err := env.db.Enqueue(context.Background(), msg); err != nil {
			t.Fatalf("enqueue message: %v", err)
		}
		msgID := msg.ID

		out, _, err := runArgs(t, append(baseFlags, "queue", "list")...)
		if err != nil || !strings.Contains(out, "Hello Queue") {
			t.Fatalf("queue list failed: %v, %s", err, out)
		}

		out, _, err = runArgs(t, append(baseFlags, "queue", "list", "--status", "queued", "--direction", "inbound", "--limit", "10")...)
		if err != nil || !strings.Contains(out, "Hello Queue") {
			t.Fatalf("queue list with flags failed: %v, %s", err, out)
		}

		if err := env.db.Quarantine(context.Background(), msgID, "spam test"); err != nil {
			t.Fatalf("quarantine message: %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "queue", "list", "--quarantined")...)
		if err != nil || !strings.Contains(out, "Hello Queue") {
			t.Fatalf("queue list quarantined failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "queue", "list")...)
		if err != nil || !strings.Contains(outJSON, `"Hello Queue"`) {
			t.Fatalf("queue list --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "queue", "show")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl queue show") {
			t.Fatalf("expected usage error for queue show, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "queue", "show", msgID)...)
		if err != nil || !strings.Contains(out, "Hello Queue") {
			t.Fatalf("queue show failed: %v, %s", err, out)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "queue", "show", msgID)...)
		if err != nil || !strings.Contains(outJSON, `"Hello Queue"`) {
			t.Fatalf("queue show --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "queue", "retry")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl queue retry") {
			t.Fatalf("expected usage error for queue retry, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "queue", "retry", msgID)...)
		if err != nil || !strings.Contains(out, "Queued for immediate delivery") {
			t.Fatalf("queue retry failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "queue", "release")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl queue release") {
			t.Fatalf("expected usage error for queue release, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "queue", "release", msgID)...)
		if err != nil || !strings.Contains(out, "Released from quarantine") {
			t.Fatalf("queue release failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "queue", "rm")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl queue rm") {
			t.Fatalf("expected usage error for queue rm, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "queue", "rm", msgID)...)
		if err != nil || !strings.Contains(out, "Deleted") {
			t.Fatalf("queue rm failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "queue", "bogus")...)
		if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
			t.Fatalf("expected unknown subcommand error for queue, got %v", err)
		}

		env.db.DeleteDomain(context.Background(), domID)
	})

	t.Run("events", func(t *testing.T) {
		env.db.RecordEvent(context.Background(), &store.Event{
			Type: "test_event", UserID: &env.adminID, Data: map[string]any{"foo": "bar"},
		})

		out, _, err := runArgs(t, append(baseFlags, "events")...)
		if err != nil || !strings.Contains(out, "test_event") {
			t.Fatalf("events failed: %v, %s", err, out)
		}

		out, _, err = runArgs(t, append(baseFlags, "events", "--limit", "5")...)
		if err != nil || !strings.Contains(out, "test_event") {
			t.Fatalf("events with limit failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "events")...)
		if err != nil || !strings.Contains(outJSON, `"test_event"`) {
			t.Fatalf("events --json failed: %v, %s", err, outJSON)
		}
	})

	t.Run("filters", func(t *testing.T) {
		out, _, err := runArgs(t, append(baseFlags, "filters", "list")...)
		if err != nil || !strings.Contains(out, "No filters configured") {
			t.Fatalf("filters list empty failed: %v, %s", err, out)
		}

		filt := &store.Filter{
			Name: "spam-subject", Field: "subject", Pattern: "*viagra*", Action: "reject", Enabled: true, Priority: 10,
		}
		if _, err := env.db.CreateFilter(context.Background(), filt); err != nil {
			t.Fatalf("create filter: %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "filters", "list")...)
		if err != nil || !strings.Contains(out, "spam-subject") {
			t.Fatalf("filters list failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "filters", "list")...)
		if err != nil || !strings.Contains(outJSON, `"spam-subject"`) {
			t.Fatalf("filters list --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "filters", "bogus")...)
		if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
			t.Fatalf("expected unknown subcommand for filters, got %v", err)
		}
	})

	t.Run("webhooks", func(t *testing.T) {
		dummyTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer dummyTarget.Close()

		hook := &store.Webhook{
			Name: "alert-hook", URL: dummyTarget.URL, Events: []string{"delivery_failed"}, Enabled: true,
		}
		hookID, err := env.db.CreateWebhook(context.Background(), hook)
		if err != nil {
			t.Fatalf("create webhook: %v", err)
		}

		out, _, err := runArgs(t, append(baseFlags, "webhooks", "list")...)
		if err != nil || !strings.Contains(out, "alert-hook") {
			t.Fatalf("webhooks list failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "webhooks", "list")...)
		if err != nil || !strings.Contains(outJSON, `"alert-hook"`) {
			t.Fatalf("webhooks list --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "webhooks", "test")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl webhooks test") {
			t.Fatalf("expected usage error for webhooks test, got %v", err)
		}

		hookIDStr := fmt.Sprintf("%d", hookID)
		out, _, err = runArgs(t, append(baseFlags, "webhooks", "test", hookIDStr)...)
		if err != nil || !strings.Contains(out, "The endpoint answered 200") {
			t.Fatalf("webhooks test failed: %v, %s", err, out)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "webhooks", "test", hookIDStr)...)
		if err != nil || !strings.Contains(outJSON, `"ok": true`) {
			t.Fatalf("webhooks test --json failed: %v, %s", err, outJSON)
		}

		out, _, err = runArgs(t, append(baseFlags, "webhooks", "deliveries")...)
		if err != nil || !strings.Contains(out, "Nothing has been delivered yet") {
			t.Fatalf("webhooks deliveries empty failed: %v, %s", err, out)
		}

		if _, err := env.db.EnqueueDelivery(context.Background(), hookID, "delivery_failed", "{}", time.Now().UTC()); err != nil {
			t.Fatalf("enqueue delivery: %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "webhooks", "deliveries", "--limit", "10", "--webhook", hookIDStr)...)
		if err != nil || !strings.Contains(out, "alert-hook") {
			t.Fatalf("webhooks deliveries populated failed: %v, %s", err, out)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "webhooks", "deliveries")...)
		if err != nil || !strings.Contains(outJSON, `"alert-hook"`) {
			t.Fatalf("webhooks deliveries --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "webhooks", "bogus")...)
		if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
			t.Fatalf("expected unknown subcommand for webhooks, got %v", err)
		}
	})

	t.Run("tokens", func(t *testing.T) {
		rawTok2, tokHash2, prefix2, err := auth.NewAPIToken()
		if err != nil {
			t.Fatalf("new token: %v", err)
		}
		_ = rawTok2
		tokRec2 := &store.APIToken{
			Name: "temp-token", Prefix: prefix2, Role: store.RoleViewer, CreatedBy: &env.adminID,
		}
		tokID2, err := env.db.CreateAPIToken(context.Background(), tokRec2, tokHash2)
		if err != nil {
			t.Fatalf("create api token: %v", err)
		}

		out, _, err := runArgs(t, append(baseFlags, "tokens", "list")...)
		if err != nil || !strings.Contains(out, "temp-token") {
			t.Fatalf("tokens list failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "tokens", "list")...)
		if err != nil || !strings.Contains(outJSON, `"temp-token"`) {
			t.Fatalf("tokens list --json failed: %v, %s", err, outJSON)
		}

		_, _, err = runArgs(t, append(baseFlags, "tokens", "rm")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl tokens rm") {
			t.Fatalf("expected usage error for tokens rm, got %v", err)
		}

		tokIDStr := fmt.Sprintf("%d", tokID2)
		out, _, err = runArgs(t, append(baseFlags, "tokens", "rm", tokIDStr)...)
		if err != nil || !strings.Contains(out, "Revoked") {
			t.Fatalf("tokens rm failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "tokens", "bogus")...)
		if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
			t.Fatalf("expected unknown subcommand for tokens, got %v", err)
		}
	})

	t.Run("cluster", func(t *testing.T) {
		out, _, err := runArgs(t, append(baseFlags, "cluster")...)
		if err != nil || !strings.Contains(out, "Clustering is off") {
			t.Fatalf("cluster disabled failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "cluster")...)
		if err != nil || !strings.Contains(outJSON, `"enabled": false`) {
			t.Fatalf("cluster disabled --json failed: %v, %s", err, outJSON)
		}

		clusterCfg := config.ClusterConfig{
			Enabled: true, Secret: "a-very-long-cluster-secret-key-16", Interval: 10 * time.Second, Timeout: time.Second,
			AdvertiseURL: "http://mx-primary:8080",
		}
		cNode := cluster.New(clusterCfg, "mx-primary", store.NodePrimary, "1.0.0", env.db, slog.New(slog.NewTextHandler(io.Discard, nil)))
		cNode.SetConfigSource(env.server)
		env.server.SetCluster(cNode)

		env.db.UpsertNode(context.Background(), &store.Node{
			ID: "mx-peer-node-1", AdvertiseURL: "http://mx-peer:8080", Version: "1.0.0", Role: store.NodeFollower,
			ConfigHash: "hash123", QueuePending: 2, QueueBytes: 2048, Domains: 1,
		})

		out, _, err = runArgs(t, append(baseFlags, "cluster")...)
		if err != nil || !strings.Contains(out, "This node: mx-primary") || !strings.Contains(out, "mx-peer-node-1") {
			t.Fatalf("cluster enabled failed: %v, %s", err, out)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "cluster")...)
		if err != nil || !strings.Contains(outJSON, `"node_id": "mx-primary"`) {
			t.Fatalf("cluster enabled --json failed: %v, %s", err, outJSON)
		}
	})

	t.Run("config", func(t *testing.T) {
		out, _, err := runArgs(t, append(baseFlags, "config", "export")...)
		if err != nil || !strings.Contains(out, "version:") {
			t.Fatalf("config export to stdout failed: %v, %s", err, out)
		}

		cfgFile := filepath.Join(tempDir, "exported-config.yaml")
		out, _, err = runArgs(t, append(baseFlags, "config", "export", cfgFile)...)
		if err != nil || !strings.Contains(out, "Written to") {
			t.Fatalf("config export to file failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "config", "import")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl config import") {
			t.Fatalf("expected usage error for config import, got %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "config", "import", cfgFile, "--dry-run")...)
		if err != nil || !strings.Contains(out, "Dry run: nothing was changed") {
			t.Fatalf("config import dry-run failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "config", "import", cfgFile, "--dry-run")...)
		if err != nil || !strings.Contains(outJSON, `"dry_run": true`) {
			t.Fatalf("config import dry-run --json failed: %v, %s", err, outJSON)
		}

		out, _, err = runArgs(t, append(baseFlags, "config", "import", cfgFile)...)
		if err != nil {
			t.Fatalf("config import apply failed: %v, %s", err, out)
		}

		_, _, err = runArgs(t, append(baseFlags, "config", "bogus")...)
		if err == nil || !strings.Contains(err.Error(), "usage: xeronmxctl config export") {
			t.Fatalf("expected usage error for config bogus, got %v", err)
		}
	})

	t.Run("drain", func(t *testing.T) {
		out, _, err := runArgs(t, append(baseFlags, "drain", "--status")...)
		if err != nil || !strings.Contains(out, "Drain mode: INACTIVE") {
			t.Fatalf("drain status inactive failed: %v, %s", err, out)
		}

		outJSON, _, err := runArgs(t, append(baseFlags, "--json", "drain", "--status")...)
		if err != nil || !strings.Contains(outJSON, `"draining": false`) {
			t.Fatalf("drain status --json failed: %v, %s", err, outJSON)
		}

		out, _, err = runArgs(t, append(baseFlags, "drain")...)
		if err != nil || !strings.Contains(out, "Drain mode enabled") {
			t.Fatalf("drain enable failed: %v, %s", err, out)
		}

		out, _, err = runArgs(t, append(baseFlags, "drain", "--status")...)
		if err != nil || !strings.Contains(out, "Drain mode: ACTIVE") {
			t.Fatalf("drain status active failed: %v, %s", err, out)
		}

		outJSON, _, err = runArgs(t, append(baseFlags, "--json", "drain")...)
		if err != nil || !strings.Contains(outJSON, `"draining": true`) {
			t.Fatalf("drain enable --json failed: %v, %s", err, outJSON)
		}

		client, err := NewClient(Settings{URL: env.ts.URL, Token: env.token})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		err = cmdDrain(canceledCtx, client, []string{"--wait"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled on canceled drain wait, got %v", err)
		}

		waitCtx, cancelWait := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelWait()
		if err := cmdDrain(waitCtx, client, []string{"--wait"}); err != nil {
			t.Fatalf("cmdDrain --wait failed on empty spool: %v", err)
		}

		out, _, err = runArgs(t, append(baseFlags, "drain", "--cancel")...)
		if err != nil || !strings.Contains(out, "Drain mode disabled") {
			t.Fatalf("drain cancel failed: %v, %s", err, out)
		}

		out, _, err = runArgs(t, append(baseFlags, "drain", "--disable")...)
		if err != nil || !strings.Contains(out, "Drain mode disabled") {
			t.Fatalf("drain disable failed: %v, %s", err, out)
		}
	})

	t.Run("auth401", func(t *testing.T) {
		_, _, err := runArgs(t, "--url", env.ts.URL, "--token", "completely-bogus-token-xyz", "status")
		if err == nil {
			t.Fatalf("expected error on unauthorized request")
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
			t.Fatalf("expected 401 APIError, got %v", err)
		}
	})
}
