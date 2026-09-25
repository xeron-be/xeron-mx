package api

import (
	"sync"
	"time"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[chan Event]struct{}
	closed  bool
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan Event]struct{})}
}

type Event struct {
	Type    string         `json:"type"`
	At      time.Time      `json:"at"`
	Payload map[string]any `json:"payload,omitempty"`
}

func (h *Hub) Notify(eventType string, payload map[string]any) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed || len(h.clients) == 0 {
		return
	}

	ev := Event{Type: eventType, At: time.Now().UTC(), Payload: payload}
	for ch := range h.clients {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (h *Hub) subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	h.clients[ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if _, ok := h.clients[ch]; ok {
				delete(h.clients, ch)
				close(ch)
			}
		})
	}
}

func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for ch := range h.clients {
		delete(h.clients, ch)
		close(ch)
	}
}

func (h *Hub) clientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
