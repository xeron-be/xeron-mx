package filter

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

func newSet(t *testing.T, rules ...*store.Filter) (*Set, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for _, r := range rules {
		if _, err := db.CreateFilter(context.Background(), r); err != nil {
			t.Fatalf("CreateFilter %s: %v", r.Name, err)
		}
	}

	s := New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s, db
}

func rule(name, field, pattern, action string, priority int) *store.Filter {
	return &store.Filter{
		Name: name, Field: field, Pattern: pattern,
		Action: action, Enabled: true, Priority: priority,
	}
}

func TestMatchesEachField(t *testing.T) {
	s, _ := newSet(t,
		rule("bad sender", store.FieldFrom, `@spam\.example$`, store.FilterReject, 10),
		rule("bad subject", store.FieldSubject, `\bviagra\b`, store.FilterQuarantine, 20),
		rule("bad rcpt", store.FieldTo, `^postmaster@`, store.FilterQuarantine, 30),
	)

	cases := []struct {
		name   string
		msg    Message
		action string
	}{
		{"sender", Message{From: "bot@spam.example"}, store.FilterReject},
		{"subject", Message{From: "a@b.test", Subject: "Cheap Viagra now"}, store.FilterQuarantine},
		{"recipient", Message{From: "a@b.test", To: []string{"postmaster@example.test"}}, store.FilterQuarantine},
		{"nothing", Message{From: "a@b.test", Subject: "hello", To: []string{"x@y.test"}}, ""},
	}
	for _, tc := range cases {
		if got := s.Evaluate(tc.msg).Action; got != tc.action {
			t.Errorf("%s: action = %q, want %q", tc.name, got, tc.action)
		}
	}
}

func TestMatchingIsCaseInsensitive(t *testing.T) {
	s, _ := newSet(t, rule("invoice", store.FieldSubject, "invoice", store.FilterQuarantine, 10))
	if !s.Evaluate(Message{Subject: "Your INVOICE is attached"}).Quarantine() {
		t.Fatal("a rule written in lower case missed an upper-case subject")
	}
}

func TestAllowAboveRejectMakesAnException(t *testing.T) {
	s, _ := newSet(t,
		rule("trusted", store.FieldFrom, `^billing@partner\.example$`, store.FilterAllow, 10),
		rule("block partner", store.FieldFrom, `@partner\.example$`, store.FilterReject, 20),
	)

	v := s.Evaluate(Message{From: "billing@partner.example"})
	if v.Action != store.FilterAllow {
		t.Fatalf("the exception did not win: action = %q", v.Action)
	}
	if v.Reject() {
		t.Fatal("an allow was treated as a reject")
	}

	if !s.Evaluate(Message{From: "someone@partner.example"}).Reject() {
		t.Fatal("the broad rule did not apply to an address the exception does not cover")
	}
}

func TestLowerPriorityWinsFirst(t *testing.T) {
	s, _ := newSet(t,
		rule("second", store.FieldSubject, "test", store.FilterReject, 50),
		rule("first", store.FieldSubject, "test", store.FilterQuarantine, 10),
	)
	if v := s.Evaluate(Message{Subject: "a test"}); v.Name != "first" {
		t.Fatalf("rule %q matched first, want the lower priority number", v.Name)
	}
}

func TestDisabledRulesAreNotLoaded(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	r := rule("off", store.FieldSubject, "test", store.FilterReject, 10)
	r.Enabled = false
	if _, err := db.CreateFilter(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	s := New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Count() != 0 {
		t.Fatalf("%d disabled rule(s) were loaded", s.Count())
	}
	if s.Evaluate(Message{Subject: "a test"}).Action != "" {
		t.Fatal("a disabled rule acted on a message")
	}
}

func TestUncompilableRuleIsSkippedNotFatal(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	if _, err := db.CreateFilter(ctx, rule("broken", store.FieldSubject, "a(b", store.FilterReject, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateFilter(ctx, rule("good", store.FieldSubject, "spam", store.FilterReject, 20)); err != nil {
		t.Fatal(err)
	}

	s := New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Load(ctx); err != nil {
		t.Fatalf("Load failed on a bad pattern instead of skipping it: %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("%d rules loaded, want only the one that compiles", s.Count())
	}
	if !s.Evaluate(Message{Subject: "spam"}).Reject() {
		t.Fatal("the good rule stopped working because a neighbour was broken")
	}
}

func TestCompileRejectsWhatItShould(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
	}{
		{"empty", ""},
		{"blank", "   "},
		{"unbalanced", "a(b"},
		{"too long", strings.Repeat("a", MaxPatternLength+1)},
	} {
		if _, err := Compile(tc.pattern); err == nil {
			t.Errorf("%s: Compile accepted %q", tc.name, tc.pattern[:min(20, len(tc.pattern))])
		}
	}
	if _, err := Compile(`^invoice.*\.pdf$`); err != nil {
		t.Errorf("a valid pattern was rejected: %v", err)
	}
}

func TestPathologicalPatternIsLinear(t *testing.T) {
	s, _ := newSet(t, rule("evil", store.FieldSubject, `(a+)+$`, store.FilterReject, 10))

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Evaluate(Message{Subject: strings.Repeat("a", 40) + "!"})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("evaluation did not finish: the regexp engine is backtracking")
	}
}

func TestVerdictReasonNamesTheRule(t *testing.T) {
	s, _ := newSet(t, rule("no invoices", store.FieldSubject, "invoice", store.FilterQuarantine, 10))

	reason := s.Evaluate(Message{Subject: "Invoice 42"}).Reason()
	for _, want := range []string{"no invoices", "subject", "Invoice 42"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
	if (Verdict{}).Reason() != "" {
		t.Error("a verdict that matched nothing produced a reason")
	}
}

func TestReloadPicksUpChanges(t *testing.T) {
	s, db := newSet(t)
	ctx := context.Background()

	if s.Evaluate(Message{Subject: "spam"}).Reject() {
		t.Fatal("something matched with no rules loaded")
	}
	if _, err := db.CreateFilter(ctx, rule("new", store.FieldSubject, "spam", store.FilterReject, 10)); err != nil {
		t.Fatal(err)
	}
	if s.Evaluate(Message{Subject: "spam"}).Reject() {
		t.Fatal("a rule acted before it was loaded")
	}
	if err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Evaluate(Message{Subject: "spam"}).Reject() {
		t.Fatal("the reload did not pick up the new rule")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	s, _ := newSet(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestTestHelperReportsWithoutSideEffects(t *testing.T) {
	rules := []*store.Filter{
		rule("block", store.FieldFrom, `@bad\.example$`, store.FilterReject, 10),
	}
	v, err := Test(rules, Message{From: "x@bad.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Reject() {
		t.Fatalf("Test did not report the match: %+v", v)
	}

	rules[0].Pattern = "a(b"
	if _, err := Test(rules, Message{From: "x@bad.example"}); err == nil {
		t.Fatal("Test accepted a pattern that does not compile")
	}
}
