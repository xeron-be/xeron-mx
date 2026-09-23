package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xeron-be/xeron-mx/internal/acme"
	"github.com/xeron-be/xeron-mx/internal/alert"
	"github.com/xeron-be/xeron-mx/internal/api"
	"github.com/xeron-be/xeron-mx/internal/authres"
	"github.com/xeron-be/xeron-mx/internal/backup"
	"github.com/xeron-be/xeron-mx/internal/blob"
	"github.com/xeron-be/xeron-mx/internal/clamav"
	"github.com/xeron-be/xeron-mx/internal/cluster"
	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/diskguard"
	"github.com/xeron-be/xeron-mx/internal/dnsbl"
	"github.com/xeron-be/xeron-mx/internal/filter"
	"github.com/xeron-be/xeron-mx/internal/health"
	"github.com/xeron-be/xeron-mx/internal/maintenance"
	"github.com/xeron-be/xeron-mx/internal/metrics"
	"github.com/xeron-be/xeron-mx/internal/oidc"
	"github.com/xeron-be/xeron-mx/internal/proxy"
	"github.com/xeron-be/xeron-mx/internal/sender"
	"github.com/xeron-be/xeron-mx/internal/smtpd"
	"github.com/xeron-be/xeron-mx/internal/spam"
	"github.com/xeron-be/xeron-mx/internal/store"
	"github.com/xeron-be/xeron-mx/internal/submission"
	"github.com/xeron-be/xeron-mx/internal/version"
	"github.com/xeron-be/xeron-mx/internal/webhook"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "xeronmx: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "", "path to xeronmx.yaml (optional; environment alone is enough)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("xeronmx", version.String())
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log)
	log.Info("starting xeronmx", "version", version.Version, "commit", version.Commit)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("database ready", "path", cfg.DBPath())

	blobs, err := blob.Open(cfg.SpoolDir(), cfg.KeyPath())
	if err != nil {
		return err
	}
	log.Info("spool ready", "path", cfg.SpoolDir())

	if err := db.RecordEvent(ctx, &store.Event{
		Type: store.EventStartup,
		Data: map[string]any{"version": version.Version, "commit": version.Commit},
	}); err != nil {
		log.Warn("startup event not recorded", "error", err)
	}

	wake := make(chan int64, 16)

	counters := &metrics.Counters{}
	var collector *metrics.Collector
	if cfg.Metrics.Enabled {
		collector = metrics.New(db, counters, cfg.Metrics.Token, log.With("component", "metrics"))
		log.Info("metrics endpoint enabled", "path", "/metrics", "token_required", cfg.Metrics.Token != "")
	}

	apiSrv := api.New(cfg.HTTP, cfg.SMTP, cfg.Queue, db, blobs, log.With("component", "api"), collector)

	alerter := alert.New(cfg.Alerts, cfg.SMTP.Hostname, log.With("component", "alerts"))
	alerter.Resume(ctx, db)
	notifier := fanOut{apiSrv.Hub(), alerter}

	spamChecker := spam.New(cfg.Spam, log.With("component", "spam"))
	if spamChecker.Enabled() {
		log.Info("spam filtering enabled", "rspamd", cfg.Spam.URL,
			"reject", cfg.Spam.RejectEnabled, "defer", cfg.Spam.DeferEnabled)
	}

	dnsblChecker := dnsbl.New(cfg.DNSBL)
	if dnsblChecker.Enabled() {
		log.Info("dnsbl reputation checks enabled", "zones", cfg.DNSBL.Zones)
	}

	clamavScanner := clamav.New(cfg.ClamAV)
	if clamavScanner.Enabled() {
		log.Info("clamav antivirus scanning enabled", "addr", cfg.ClamAV.Addr, "action", cfg.ClamAV.Action)
	}

	filters := filter.New(db, log.With("component", "filters"))
	apiSrv.SetFilters(filters)
	apiSrv.SetOutbound(cfg.Outbound)
	apiSrv.SetDNSBL(dnsblChecker)
	apiSrv.SetClamAV(clamavScanner)
	apiSrv.SetSpam(spamChecker)

	maintMgr := maintenance.NewManager(cfg.Maintenance.Drain)
	if maintMgr.IsDraining() {
		log.Warn("starting in maintenance drain mode", "component", "maintenance")
	}
	apiSrv.SetMaintenance(maintMgr)
	apiSrv.SetDiskGuard(cfg.SpoolDir(), cfg.Queue.MinFreeDiskBytes, diskguard.DefaultCheck)

	nodeID := cfg.ClusterNodeID()

	hooks := webhook.New(cfg.Webhooks, db, blobs, nodeID, log.With("component", "webhooks"))
	apiSrv.SetWebhooks(hooks)

	sso := oidc.New(cfg.OIDC, cfg.OIDCRedirectURL(), log.With("component", "oidc"))
	apiSrv.SetOIDC(sso)

	node := cluster.New(cfg.Cluster, nodeID, cfg.ClusterRole(), version.Version,
		db, log.With("component", "cluster"))
	node.SetConfigSource(apiSrv)
	apiSrv.SetCluster(node)

	smtpSrv, err := smtpd.New(cfg.SMTP, cfg.Queue, db, blobs,
		log.With("component", "smtpd"), notifier, counters, spamChecker, filters)
	if err != nil {
		return err
	}
	smtpSrv.SetDNSBL(dnsblChecker)
	smtpSrv.SetClamAV(clamavScanner)
	if cfg.SMTP.SenderAuth {
		smtpSrv.SetAuthChecker(&authres.Checker{})
	}
	smtpSrv.SetMaintenance(maintMgr)
	smtpSrv.SetDiskGuard(cfg.SpoolDir(), cfg.Queue.MinFreeDiskBytes, diskguard.DefaultCheck)
	checker := health.New(cfg.Health, db, log.With("component", "health"), notifier, wake, counters)
	deliverer := sender.New(cfg.Queue, db, blobs, log.With("component", "sender"),
		notifier, wake, counters, cfg.Outbound, cfg.SMTP.Hostname)

	var submissionSrv *submission.Server
	if cfg.Outbound.Enabled {
		submissionSrv = submission.New(cfg.Outbound, cfg.Queue, db, blobs,
			log.With("component", "submission"), notifier, counters)
		submissionSrv.SetHostname(cfg.SMTP.Hostname)
		if trusted, err := proxy.ParseTrusted(cfg.SMTP.ProxyProtocolTrusted); err == nil {
			submissionSrv.SetProxyTrusted(trusted)
		}
		submissionSrv.SetMaintenance(maintMgr)
		submissionSrv.SetDiskGuard(cfg.SpoolDir(), cfg.Queue.MinFreeDiskBytes, diskguard.DefaultCheck)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	if cfg.HTTP.ACME.Enabled {
		mgr, err := acme.New(cfg.HTTP.ACME, cfg.ACMECacheDir(), log.With("component", "acme"))
		if err != nil {
			return err
		}
		apiSrv.SetTLSConfig(mgr.TLSConfig())
		apiSrv.SetCertificateReporter(mgr)
		smtpSrv.SetTLSConfig(mgr.SMTPTLSConfig())
		if submissionSrv != nil {

			submissionSrv.SetTLSConfig(mgr.SMTPTLSConfig())
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mgr.RunChallengeServer(ctx); err != nil {

				log.Error("acme challenge server stopped", "error", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Run(ctx)
		}()
	} else if submissionSrv != nil && cfg.SMTP.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.SMTP.TLSCert, cfg.SMTP.TLSKey)
		if err != nil {
			return fmt.Errorf("submission: load smtp TLS keypair: %w", err)
		}
		submissionSrv.SetTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := smtpSrv.ListenAndServe(ctx); err != nil {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := apiSrv.ListenAndServe(ctx); err != nil {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	if submissionSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := submissionSrv.ListenAndServe(ctx); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		filters.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		alerter.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		hooks.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sso.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		node.Run(ctx)
	}()

	backups := backup.New(cfg.Backup, cfg.BackupDir(), db, log.With("component", "backup"))
	wg.Add(1)
	go func() {
		defer wg.Done()
		backups.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		checker.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		deliverer.Run(ctx)
	}()

	log.Info("xeronmx is running")

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, draining")
	case runErr = <-errCh:
		log.Error("component failed, shutting down", "error", runErr)
		stop()
	}

	if err := smtpSrv.Shutdown(); err != nil {
		log.Warn("smtp shutdown", "error", err)
	}
	if submissionSrv != nil {
		if err := submissionSrv.Shutdown(); err != nil {
			log.Warn("submission shutdown", "error", err)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Info("stopped cleanly")
	case <-time.After(30 * time.Second):

		log.Warn("shutdown timed out, exiting anyway")
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

type notifier interface {
	Notify(event string, payload map[string]any)
}

type fanOut []notifier

func (f fanOut) Notify(event string, payload map[string]any) {
	for _, n := range f {
		n.Notify(event, payload)
	}
}

func newLogger(cfg config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "text") {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
