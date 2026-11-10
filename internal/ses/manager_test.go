package ses_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"github.com/xeron-be/xeron-mx/internal/ses"
	"github.com/xeron-be/xeron-mx/internal/ses/sestest"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type recorder struct{ events []string }

func (r *recorder) Notify(event string, _ map[string]any) { r.events = append(r.events, event) }

type fixture struct {
	db     *store.DB
	fake   *sestest.Fake
	m      *ses.Manager
	notify *recorder
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &fixture{db: db, fake: sestest.New(), notify: &recorder{}}
	f.m = ses.NewManager(f.fake, db, slog.New(slog.NewTextHandler(io.Discard, nil)), f.notify,
		"eu-west-3", 0, "mx.xeron.example")
	return f
}

func (f *fixture) domain(t *testing.T, name string) *store.Domain {
	t.Helper()
	id, err := f.db.CreateDomain(context.Background(), &store.Domain{
		Name: name, PrimaryHost: "mail." + name, PrimaryPort: 25, PrimaryTLS: "starttls",
		RetentionHours: 168, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := f.db.DomainByID(context.Background(), id)
	return d
}

func (f *fixture) row(t *testing.T, d *store.Domain) *store.SESIdentity {
	t.Helper()
	r, err := f.db.SESIdentityFor(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) pass(t *testing.T) {
	t.Helper()
	if err := f.m.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestANewDomainGetsItsOwnIdentity(t *testing.T) {
	f := setup(t)
	d := f.domain(t, "client.example")
	f.pass(t)

	r := f.row(t, d)
	if r.Identity != "client.example" || r.Inherited || !r.Managed || r.Status != store.SESPending {
		t.Fatalf("row = %+v", r)
	}
	if len(r.DKIMTokens) != 3 {
		t.Fatalf("the three DKIM tokens were not kept: %v", r.DKIMTokens)
	}
	if !slices.Equal(f.fake.Creates, []string{"client.example"}) {
		t.Fatalf("creates = %v", f.fake.Creates)
	}

	f.fake.SetStatus("client.example", ses.StatusSuccess)
	f.pass(t)
	if r := f.row(t, d); r.Status != store.SESVerified || r.LastError != "" {
		t.Fatalf("after verification: %+v", r)
	}
	if !slices.Contains(f.notify.events, store.EventSESVerified) {
		t.Fatalf("no verified event: %v", f.notify.events)
	}
	if len(f.fake.Creates) != 1 {
		t.Fatalf("the identity was created again: %v", f.fake.Creates)
	}
}

func TestASubdomainOfAVerifiedParentCreatesNothing(t *testing.T) {
	f := setup(t)
	f.fake.Put("xeron.example", ses.StatusSuccess)
	d := f.domain(t, "client.xeron.example")
	f.pass(t)

	r := f.row(t, d)
	if r.Identity != "xeron.example" || !r.Inherited || r.Managed || r.Status != store.SESVerified {
		t.Fatalf("row = %+v", r)
	}
	if len(f.fake.Creates) != 0 {
		t.Fatalf("an identity was created for a covered subdomain: %v", f.fake.Creates)
	}
	if len(r.DKIMTokens) != 0 {
		t.Fatalf("an inherited identity has nothing to publish, got %v", r.DKIMTokens)
	}
}

func TestASubdomainWaitsForAPendingParent(t *testing.T) {
	f := setup(t)
	f.fake.Put("xeron.example", ses.StatusPending)
	d := f.domain(t, "a.b.xeron.example")
	f.pass(t)

	if r := f.row(t, d); r.Identity != "xeron.example" || !r.Inherited || r.Status != store.SESPending {
		t.Fatalf("row = %+v", r)
	}
	if len(f.fake.Creates) != 0 {
		t.Fatalf("creates = %v", f.fake.Creates)
	}
	f.fake.SetStatus("xeron.example", ses.StatusSuccess)
	f.pass(t)
	if r := f.row(t, d); r.Status != store.SESVerified {
		t.Fatalf("the subdomain did not follow its parent: %+v", r)
	}
}

func TestAFailedParentIsNotInherited(t *testing.T) {
	f := setup(t)
	f.fake.Put("xeron.example", ses.StatusFailed)
	d := f.domain(t, "client.xeron.example")
	f.pass(t)

	if r := f.row(t, d); r.Identity != "client.xeron.example" || r.Inherited || !r.Managed {
		t.Fatalf("row = %+v", r)
	}
}

func TestAnIdentityCreatedByHandIsAdoptedNotOwned(t *testing.T) {
	f := setup(t)
	f.fake.Put("xeron.example", ses.StatusPending)
	d := f.domain(t, "xeron.example")
	f.pass(t)

	r := f.row(t, d)
	if r.Identity != "xeron.example" || r.Managed || r.Inherited {
		t.Fatalf("row = %+v", r)
	}
	if _, _, err := f.m.Deletable(context.Background(), d); !errors.Is(err, ses.ErrNotManaged) {
		t.Fatalf("an adopted identity could be deleted: %v", err)
	}
}

func TestAnSESOutageKeepsTheLastKnownStatus(t *testing.T) {
	f := setup(t)
	f.fake.Put("client.example", ses.StatusSuccess)
	d := f.domain(t, "client.example")
	f.pass(t)

	f.fake.Err = errors.New("dial tcp: i/o timeout")
	f.pass(t)
	r := f.row(t, d)
	if r.Status != store.SESVerified || r.LastError == "" {
		t.Fatalf("row = %+v; want still verified, with the error noted", r)
	}
}

func TestAnUnreachableSESBeforeAnyIdentityIsAnError(t *testing.T) {
	f := setup(t)
	f.fake.Err = errors.New("AccessDeniedException")
	d := f.domain(t, "client.example")
	f.pass(t)
	if r := f.row(t, d); r.Status != store.SESError || r.Identity != "" || r.LastError == "" {
		t.Fatalf("row = %+v", r)
	}

	f.fake.Err = nil
	f.pass(t)
	if r := f.row(t, d); r.Status != store.SESPending || r.LastError != "" || !r.Managed {
		t.Fatalf("no recovery once SES answered again: %+v", r)
	}
}

func TestAnIdentityDeletedInSESIsCreatedAgain(t *testing.T) {
	f := setup(t)
	d := f.domain(t, "client.example")
	f.pass(t)
	if err := f.fake.DeleteIdentity(context.Background(), "client.example"); err != nil {
		t.Fatal(err)
	}
	f.pass(t)
	if !f.fake.Has("client.example") || len(f.fake.Creates) != 2 {
		t.Fatalf("creates = %v", f.fake.Creates)
	}
	if r := f.row(t, d); !r.Managed || r.Status != store.SESPending {
		t.Fatalf("row = %+v", r)
	}
}

func TestAFailedVerificationIsAnnounced(t *testing.T) {
	f := setup(t)
	d := f.domain(t, "client.example")
	f.pass(t)
	f.fake.SetStatus("client.example", ses.StatusFailed)
	f.pass(t)
	if r := f.row(t, d); r.Status != store.SESFailed {
		t.Fatalf("row = %+v", r)
	}
	if !slices.Contains(f.notify.events, store.EventSESFailed) {
		t.Fatalf("events = %v", f.notify.events)
	}
}

func TestDeletionIsRefusedWhileSubdomainsInherit(t *testing.T) {
	f := setup(t)
	parent := f.domain(t, "xeron.example")
	f.pass(t)
	child := f.domain(t, "client.xeron.example")
	f.pass(t)

	if r := f.row(t, child); r.Identity != "xeron.example" || !r.Inherited {
		t.Fatalf("child = %+v", r)
	}
	_, deps, err := f.m.Deletable(context.Background(), parent)
	if !errors.Is(err, ses.ErrInUse) || !slices.Equal(deps, []string{"client.xeron.example"}) {
		t.Fatalf("deletable = %v, %v", deps, err)
	}
	if err := f.m.DeleteIdentity(context.Background(), parent); !errors.Is(err, ses.ErrInUse) {
		t.Fatalf("delete = %v", err)
	}
	if !f.fake.Has("xeron.example") {
		t.Fatal("the parent identity was deleted from under its subdomains")
	}
}

func TestDeletionOfAnOwnedIdentity(t *testing.T) {
	f := setup(t)
	d := f.domain(t, "client.example")
	f.pass(t)
	if err := f.m.DeleteIdentity(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if f.fake.Has("client.example") {
		t.Fatal("still in SES")
	}
	if _, err := f.db.SESIdentityFor(context.Background(), d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row left behind: %v", err)
	}
}

func TestOnePassLooksUpASharedParentOnce(t *testing.T) {
	f := setup(t)
	f.fake.Put("xeron.example", ses.StatusSuccess)
	for _, n := range []string{"a.xeron.example", "b.xeron.example", "c.xeron.example"} {
		f.domain(t, n)
	}
	f.fake.Gets = nil
	f.pass(t)
	n := 0
	for _, g := range f.fake.Gets {
		if g == "xeron.example" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("xeron.example looked up %d times in one pass: %v", n, f.fake.Gets)
	}
}

func TestBounceSenderCoverage(t *testing.T) {
	f := setup(t)
	f.pass(t)
	if b := f.m.BounceSender(); b.Status != store.SESFailed || b.Sender != "MAILER-DAEMON@mx.xeron.example" {
		t.Fatalf("with no identity: %+v", b)
	}
	f.fake.Put("xeron.example", ses.StatusSuccess)
	f.pass(t)
	if b := f.m.BounceSender(); b.Status != store.SESVerified || b.Identity != "xeron.example" {
		t.Fatalf("covered by its parent: %+v", b)
	}
}

func TestCheckRecordsOneDomainAtOnce(t *testing.T) {
	f := setup(t)
	d := f.domain(t, "client.example")
	r, err := f.m.Check(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity != "client.example" || r.CheckedAt == nil {
		t.Fatalf("row = %+v", r)
	}
}
