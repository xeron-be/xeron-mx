package ratelimit

import (
	"sync"
	"time"
)

const maxKeys = 10000

type Limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	attempts map[string][]time.Time
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, attempts: make(map[string][]time.Time)}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	kept := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)

	if len(l.attempts) > maxKeys {
		for k, v := range l.attempts {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(l.attempts, k)
			}
		}
	}
	return true
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
