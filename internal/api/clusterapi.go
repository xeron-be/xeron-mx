package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/xeron-be/xeron-mx/internal/cluster"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const maxClusterBody = 1 << 20

func (s *Server) peerRequest(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if s.cluster == nil || !s.cluster.Enabled() {
		s.fail(w, r, http.StatusNotFound, ErrNotFound)
		return nil, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxClusterBody))
	if err != nil {
		s.fail(w, r, http.StatusRequestEntityTooLarge, ErrRequestTooLarge)
		return nil, false
	}

	peer, err := cluster.Verify(r, s.cluster.Secret(), s.cluster.ID(), body)
	if err != nil {
		s.log.Warn("cluster: refused a peer call",
			"path", r.URL.Path, "ip", clientIP(r), "reason", err)
		s.fail(w, r, http.StatusUnauthorized, ErrClusterUnauthorized)
		return nil, false
	}
	s.log.Debug("cluster call accepted", "peer", peer, "path", r.URL.Path)
	return body, true
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	body, ok := s.peerRequest(w, r)
	if !ok {
		return
	}

	var hb cluster.Heartbeat
	if err := json.Unmarshal(body, &hb); err != nil || hb.NodeID == "" {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidHeartbeat)
		return
	}
	if err := s.cluster.Observe(r.Context(), &hb); err != nil {
		s.log.Error("cluster: could not record a peer", "peer", hb.NodeID, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrPeerRecordFailed)
		return
	}

	self, err := s.cluster.Snapshot(r.Context())
	if err != nil {
		s.log.Error("cluster: could not describe this node", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrClusterDescribeFailed)
		return
	}
	s.ok(w, http.StatusOK, self)
}

func (s *Server) handleClusterConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.peerRequest(w, r); !ok {
		return
	}

	body, err := s.ExportConfigYAML(r.Context())
	if err != nil {
		s.log.Error("cluster: could not render the configuration", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrConfigReadFailed)
		return
	}
	s.ok(w, http.StatusOK, map[string]any{"yaml": string(body)})
}

type nodeView struct {
	ID           string    `json:"node_id"`
	AdvertiseURL string    `json:"advertise_url,omitempty"`
	Version      string    `json:"version,omitempty"`
	Role         string    `json:"role"`
	ConfigHash   string    `json:"config_hash,omitempty"`
	QueuePending int64     `json:"queue_pending"`
	QueueBytes   int64     `json:"queue_bytes"`
	Domains      int64     `json:"domains"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Healthy      bool      `json:"healthy"`
	Self         bool      `json:"self"`
	ConfigDrift  bool      `json:"config_drift"`
}

func (s *Server) handleClusterState(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil || !s.cluster.Enabled() {
		s.ok(w, http.StatusOK, map[string]any{"enabled": false, "nodes": []nodeView{}})
		return
	}

	nodes, err := s.db.ListNodes(r.Context())
	if err != nil {
		s.log.Error("could not list cluster nodes", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrFleetReadFailed)
		return
	}

	selfID := s.cluster.ID()
	within := s.cluster.HealthyWithin()
	now := time.Now().UTC()

	var ours string
	for _, n := range nodes {
		if n.ID == selfID {
			ours = n.ConfigHash
		}
	}

	out := make([]nodeView, 0, len(nodes))
	var healthy, drifted int
	for _, n := range nodes {
		v := nodeView{
			ID: n.ID, AdvertiseURL: n.AdvertiseURL, Version: n.Version,
			Role: n.Role, ConfigHash: n.ConfigHash,
			QueuePending: n.QueuePending, QueueBytes: n.QueueBytes,
			Domains: n.Domains, FirstSeen: n.FirstSeen, LastSeen: n.LastSeen,
			Healthy: n.Healthy(now, within), Self: n.ID == selfID,
		}
		if ours != "" && n.ConfigHash != "" && n.ConfigHash != ours {
			v.ConfigDrift = true
			drifted++
		}
		if v.Healthy {
			healthy++
		}
		out = append(out, v)
	}

	s.ok(w, http.StatusOK, map[string]any{
		"enabled":         true,
		"node_id":         selfID,
		"role":            s.cluster.Role(),
		"healthy_after":   int(within.Seconds()),
		"nodes":           out,
		"healthy":         healthy,
		"drifted":         drifted,
		"queue_is_shared": false,
	})
}

func (s *Server) handleForgetNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidNodeID)
		return
	}
	if s.cluster != nil && id == s.cluster.ID() {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidNodeID)
		return
	}

	admin := userFrom(r)
	if err := s.db.DeleteNode(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrNodeNotFound)
			return
		}
		s.log.Error("could not forget a cluster node", "node", id, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrNodeForgetFailed)
		return
	}

	s.log.Warn("cluster node forgotten", "node", id, "by", admin.Email)
	s.ok(w, http.StatusOK, map[string]any{"forgotten": id})
}
