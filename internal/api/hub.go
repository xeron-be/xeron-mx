package api

import (
	"encoding/json"
	"sync"
	"time"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
	closed  bool
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan []byte]struct{})}
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

	raw, err := json.Marshal(Event{Type: eventType, At: time.Now().UTC(), Payload: payload})
	if err != nil {
		return
	}
	for ch := range h.clients {
		select {
		case ch <- raw:
		default:
		}
	}
}

func (h *Hub) subscribe() (<-chan []byte, func()) {

	ch := make(chan []byte, 32)

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
