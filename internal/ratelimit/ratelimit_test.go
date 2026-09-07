package ratelimit

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestAllowStopsAtTheBudget(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("192.0.2.1") {
			t.Fatalf("attempt %d was refused inside the budget", i+1)
		}
	}
	if l.Allow("192.0.2.1") {
		t.Fatal("the attempt over the budget was allowed")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, time.Minute)
	if !l.Allow("192.0.2.1") {
		t.Fatal("first key refused")
	}
	if !l.Allow("192.0.2.2") {
		t.Fatal("one address exhausting its budget must not throttle another")
	}
}

func TestResetClearsTheHistory(t *testing.T) {
	l := New(2, time.Minute)
	l.Allow("192.0.2.1")
	l.Allow("192.0.2.1")
	if l.Allow("192.0.2.1") {
		t.Fatal("budget was not exhausted")
	}
	l.Reset("192.0.2.1")
	if !l.Allow("192.0.2.1") {
		t.Fatal("Reset did not clear the history")
	}
}

func TestAttemptsExpireWithTheWindow(t *testing.T) {
	l := New(1, 40*time.Millisecond)
	if !l.Allow("192.0.2.1") {
		t.Fatal("first attempt refused")
	}
	if l.Allow("192.0.2.1") {
		t.Fatal("second attempt allowed inside the window")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("192.0.2.1") {
		t.Fatal("the window did not expire")
	}
}

func TestConcurrentCallersNeverExceedTheBudget(t *testing.T) {
	const budget = 10
	l := New(budget, time.Minute)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	start := make(chan struct{})
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l.Allow("192.0.2.1") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if allowed != budget {
		t.Fatalf("SECURITY: %d concurrent attempts were allowed, want exactly %d", allowed, budget)
	}
}

func TestTrackingMapIsSwept(t *testing.T) {
	l := New(1, time.Millisecond)
	for i := 0; i < maxKeys+50; i++ {
		l.Allow(strconv.Itoa(i))
	}

	time.Sleep(5 * time.Millisecond)
	l.Allow("trigger-the-sweep")

	l.mu.Lock()
	n := len(l.attempts)
	l.mu.Unlock()
	if n > maxKeys {
		t.Fatalf("tracking map holds %d keys after a sweep, want at most %d", n, maxKeys)
	}
}
