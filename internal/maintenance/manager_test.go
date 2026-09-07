package maintenance

import (
	"sync"
	"testing"
)

func TestManager(t *testing.T) {
	m := NewManager(false)
	if m.IsDraining() {
		t.Fatal("expected IsDraining to be false")
	}

	m.SetDraining(true)
	if !m.IsDraining() {
		t.Fatal("expected IsDraining to be true")
	}

	m.SetDraining(false)
	if m.IsDraining() {
		t.Fatal("expected IsDraining to be false")
	}

	var nilManager *Manager
	if nilManager.IsDraining() {
		t.Fatal("expected nil manager IsDraining to be false")
	}
	nilManager.SetDraining(true)
}

func TestManagerConcurrent(t *testing.T) {
	m := NewManager(false)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(val bool) {
			defer wg.Done()
			m.SetDraining(val)
		}(i%2 == 0)
		go func() {
			defer wg.Done()
			_ = m.IsDraining()
		}()
	}
	wg.Wait()
}
