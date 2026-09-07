package maintenance

import (
	"sync/atomic"
)

type Manager struct {
	draining atomic.Bool
}

func NewManager(initialDrain bool) *Manager {
	m := &Manager{}
	m.draining.Store(initialDrain)
	return m
}

func (m *Manager) IsDraining() bool {
	if m == nil {
		return false
	}
	return m.draining.Load()
}

func (m *Manager) SetDraining(v bool) {
	if m == nil {
		return
	}
	m.draining.Store(v)
}
