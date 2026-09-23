package backup

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func newRunner(t *testing.T, cfg config.BackupConfig) (*Runner, *store.DB, string) {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(context.Background(), filepath.Join(dir, "xeronmx.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	out := filepath.Join(dir, "backups")
	cfg.Enabled = true
	return New(cfg, out, db, slog.New(slog.NewTextHandler(io.Discard, nil))), db, out
}

func snapshots(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filePrefix) && strings.HasSuffix(e.Name(), fileSuffix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestSnapshotIsARestorableDatabase(t *testing.T) {
	r, db, _ := newRunner(t, config.BackupConfig{Keep: 7})
	ctx := context.Background()

	if _, err := db.CreateDomain(ctx, &store.Domain{
		Name: "example.test", PrimaryHost: "mail.example.test", PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	path, err := r.Once(ctx)
	if err != nil {
		t.Fatalf("Once: %v", err)
	}

	restored, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("the snapshot does not open as a database: %v", err)
	}
	defer restored.Close()

	d, err := restored.DomainByName(ctx, "example.test")
	if err != nil {
		t.Fatalf("the domain is missing from the snapshot: %v", err)
	}
	if d.PrimaryHost != "mail.example.test" {
		t.Fatalf("restored domain is wrong: %+v", d)
	}
}

func TestSnapshotIsTakenWhileTheDatabaseIsBeingWritten(t *testing.T) {
	r, db, _ := newRunner(t, config.BackupConfig{Keep: 7})
	ctx := context.Background()

	id, err := db.CreateDomain(ctx, &store.Domain{
		Name: "busy.test", PrimaryHost: "mail.busy.test", PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				db.RecordEvent(ctx, &store.Event{Type: "mail_received", DomainID: &id})
			}
		}
	}()

	path, err := r.Once(ctx)
	close(stop)
	<-done
	if err != nil {
		t.Fatalf("snapshotting a live database failed: %v", err)
	}

	restored, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("the snapshot taken under write load is not a valid database: %v", err)
	}
	restored.Close()
}

func TestRetentionKeepsTheNewest(t *testing.T) {
	r, _, dir := newRunner(t, config.BackupConfig{Keep: 3})

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{
		"xeronmx-20260101-000000.db",
		"xeronmx-20260102-000000.db",
		"xeronmx-20260103-000000.db",
		"xeronmx-20260104-000000.db",
		"xeronmx-20260105-000000.db",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.prune(); err != nil {
		t.Fatal(err)
	}

	got := snapshots(t, dir)
	if len(got) != 3 {
		t.Fatalf("%d snapshots kept, want 3: %v", len(got), got)
	}
	for _, want := range []string{
		"xeronmx-20260103-000000.db",
		"xeronmx-20260104-000000.db",
		"xeronmx-20260105-000000.db",
	} {
		found := false
		for _, n := range got {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was pruned, but it is among the newest", want)
		}
	}
}

func TestRetentionOfZeroKeepsEverything(t *testing.T) {
	r, _, dir := newRunner(t, config.BackupConfig{Keep: 0})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := r.Once(ctx); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond)
	}
	if n := len(snapshots(t, dir)); n != 3 {
		t.Fatalf("%d snapshots with keep: 0, want 3", n)
	}
}

func TestSnapshotsAreNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	r, _, dir := newRunner(t, config.BackupConfig{Keep: 7})

	path, err := r.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("snapshot mode is %04o, want no group or world access", mode)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := di.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("backup directory mode is %04o, want no group or world access", mode)
	}
}

func TestDisabledRunnerDoesNothing(t *testing.T) {
	r, _, dir := newRunner(t, config.BackupConfig{})
	r.cfg.Enabled = false

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run did not return immediately when disabled")
	}
	cancel()

	if n := len(snapshots(t, dir)); n != 0 {
		t.Fatalf("%d snapshots written while disabled", n)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	r, _, _ := newRunner(t, config.BackupConfig{Interval: time.Hour, Keep: 7})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func runFor(t *testing.T, r *Runner, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	r.Run(ctx)
}

func TestAStartWithoutARecentSnapshotTakesOneAtOnce(t *testing.T) {
	r, _, dir := newRunner(t, config.BackupConfig{Interval: time.Hour, Keep: 7})

	runFor(t, r, 300*time.Millisecond)
	if n := len(snapshots(t, dir)); n != 1 {
		t.Fatalf("%d snapshots after a start with none; want one taken at once, not an hour later", n)
	}

	runFor(t, r, 300*time.Millisecond)
	if n := len(snapshots(t, dir)); n != 1 {
		t.Fatalf("%d snapshots after a restart minutes later; want the recent one kept, no new one", n)
	}

	old := time.Now().Add(-2 * time.Hour)
	for _, name := range snapshots(t, dir) {
		if err := os.Chtimes(filepath.Join(dir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	runFor(t, r, 300*time.Millisecond)
	if n := len(snapshots(t, dir)); n != 2 {
		t.Fatalf("%d snapshots after a restart with a stale one; want a fresh one", n)
	}
}
