package filter

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	MaxPatternLength = 500
	reloadInterval   = 30 * time.Second
)

type Verdict struct {
	Action   string
	FilterID int64
	Name     string
	Field    string
	Matched  string
}

func (v Verdict) Reject() bool     { return v.Action == store.FilterReject }
func (v Verdict) Quarantine() bool { return v.Action == store.FilterQuarantine }

func (v Verdict) Reason() string {
	if v.Name == "" {
		return ""
	}
	return fmt.Sprintf("matched filter %q on %s: %s", v.Name, v.Field, v.Matched)
}

type Message struct {
	From    string
	To      []string
	Subject string
}

type compiled struct {
	rule *store.Filter
	re   *regexp.Regexp
}

type Set struct {
	db  *store.DB
	log *slog.Logger

	mu       sync.RWMutex
	rules    []compiled
	loadedAt time.Time
}

func New(db *store.DB, log *slog.Logger) *Set {
	return &Set{db: db, log: log}
}

func Compile(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("the pattern is empty")
	}
	if len(pattern) > MaxPatternLength {
		return nil, fmt.Errorf("the pattern is longer than %d characters", MaxPatternLength)
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, err
	}
	return re, nil
}

func (s *Set) Load(ctx context.Context) error {
	rules, err := s.db.ListFilters(ctx)
	if err != nil {
		return err
	}

	out := make([]compiled, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := Compile(r.Pattern)
		if err != nil {
			s.log.Error("filter skipped: its pattern does not compile",
				"filter", r.Name, "id", r.ID, "error", err)
			continue
		}
		out = append(out, compiled{rule: r, re: re})
	}

	s.mu.Lock()
	s.rules = out
	s.loadedAt = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *Set) Run(ctx context.Context) {
	if err := s.Load(ctx); err != nil {
		s.log.Error("could not load filters", "error", err)
	}
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Load(ctx); err != nil {
				s.log.Error("could not reload filters", "error", err)
			}
		}
	}
}

func (s *Set) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

func (s *Set) Evaluate(m Message) Verdict {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	for _, c := range rules {
		matched, ok := match(c, m)
		if !ok {
			continue
		}
		if c.rule.Action == store.FilterAllow {
			return Verdict{Action: store.FilterAllow, FilterID: c.rule.ID,
				Name: c.rule.Name, Field: c.rule.Field, Matched: matched}
		}
		return Verdict{Action: c.rule.Action, FilterID: c.rule.ID,
			Name: c.rule.Name, Field: c.rule.Field, Matched: matched}
	}
	return Verdict{}
}

func match(c compiled, m Message) (string, bool) {
	switch c.rule.Field {
	case store.FieldFrom:
		if c.re.MatchString(m.From) {
			return m.From, true
		}
	case store.FieldSubject:
		if c.re.MatchString(m.Subject) {
			return m.Subject, true
		}
	case store.FieldTo:
		for _, rcpt := range m.To {
			if c.re.MatchString(rcpt) {
				return rcpt, true
			}
		}
	}
	return "", false
}

func Test(rules []*store.Filter, m Message) (Verdict, error) {
	set := make([]compiled, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := Compile(r.Pattern)
		if err != nil {
			return Verdict{}, fmt.Errorf("filter %q: %w", r.Name, err)
		}
		set = append(set, compiled{rule: r, re: re})
	}
	for _, c := range set {
		if matched, ok := match(c, m); ok {
			return Verdict{Action: c.rule.Action, FilterID: c.rule.ID,
				Name: c.rule.Name, Field: c.rule.Field, Matched: matched}, nil
		}
	}
	return Verdict{}, nil
}
