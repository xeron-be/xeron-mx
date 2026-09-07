package backup

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	filePrefix = "xeronmx-"
	fileSuffix = ".db"
	stamp      = "20060102-150405"
)

type Runner struct {
	cfg config.BackupConfig
	dir string
	db  *store.DB
	log *slog.Logger

	last   time.Time
	lastOK bool
}

func New(cfg config.BackupConfig, dir string, db *store.DB, log *slog.Logger) *Runner {
	return &Runner{cfg: cfg, dir: dir, db: db, log: log}
}

func (r *Runner) Enabled() bool { return r.cfg.Enabled }

func (r *Runner) Run(ctx context.Context) {
	if !r.cfg.Enabled {
		return
	}
	interval := r.cfg.Interval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	r.log.Info("automatic backups enabled", "dir", r.dir, "interval", interval.String(), "keep", r.cfg.Keep)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := r.Once(ctx); err != nil {
				r.log.Error("backup failed", "error", err)
			}
		}
	}
}

func (r *Runner) Once(ctx context.Context) (string, error) {
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return "", fmt.Errorf("backup: create directory: %w", err)
	}
	_ = os.Chmod(r.dir, 0o700)

	name := filePrefix + time.Now().UTC().Format(stamp) + fileSuffix
	path := filepath.Join(r.dir, name)

	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return "", fmt.Errorf("backup: clear the previous file at %s: %w", path, err)
		}
	}

	start := time.Now()
	if err := r.db.Snapshot(ctx, path); err != nil {
		r.note(false)
		return "", err
	}
	_ = os.Chmod(path, 0o600)

	size := int64(0)
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	r.note(true)
	r.log.Info("backup written", "file", name, "bytes", size, "took", time.Since(start).String())

	if err := r.prune(); err != nil {
		r.log.Warn("could not prune old backups", "error", err)
	}
	return path, nil
}

func (r *Runner) note(ok bool) {
	r.last = time.Now().UTC()
	r.lastOK = ok
}

func (r *Runner) prune() error {
	keep := r.cfg.Keep
	if keep <= 0 {
		return nil
	}

	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, filePrefix) && strings.HasSuffix(n, fileSuffix) {
			names = append(names, n)
		}
	}
	if len(names) <= keep {
		return nil
	}

	sort.Strings(names)
	for _, n := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(r.dir, n)); err != nil {
			return err
		}
		r.log.Debug("old backup removed", "file", n)
	}
	return nil
}
