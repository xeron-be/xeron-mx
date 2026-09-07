package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	HeartbeatPath = "/api/v1/cluster/heartbeat"
	ConfigPath    = "/api/v1/cluster/config"

	healthyIntervals = 3

	forgetAfter = 7 * 24 * time.Hour

	maxBodyBytes = 1 << 20
)

type ConfigSource interface {
	ExportConfigYAML(ctx context.Context) ([]byte, error)
	ApplyConfigYAML(ctx context.Context, raw []byte, dryRun bool) (map[string]any, error)
	ConfigHash(ctx context.Context) (string, error)
}

type Heartbeat struct {
	NodeID       string    `json:"node_id"`
	AdvertiseURL string    `json:"advertise_url"`
	Version      string    `json:"version"`
	Role         string    `json:"role"`
	ConfigHash   string    `json:"config_hash"`
	QueuePending int64     `json:"queue_pending"`
	QueueBytes   int64     `json:"queue_bytes"`
	Domains      int64     `json:"domains"`
	At           time.Time `json:"at"`
}

type Node struct {
	cfg     config.ClusterConfig
	db      *store.DB
	log     *slog.Logger
	id      string
	role    string
	version string
	configs ConfigSource
	client  *http.Client
}

func New(cfg config.ClusterConfig, nodeID, role, version string, db *store.DB, log *slog.Logger) *Node {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if role != store.NodePrimary {
		role = store.NodeFollower
	}
	return &Node{
		cfg:     cfg,
		db:      db,
		log:     log,
		id:      nodeID,
		role:    role,
		version: version,
		client:  &http.Client{Timeout: timeout},
	}
}

func (n *Node) Enabled() bool { return n.cfg.Enabled }

func (n *Node) ID() string { return n.id }

func (n *Node) Secret() string { return n.cfg.Secret }

func (n *Node) Role() string { return n.role }

func (n *Node) SetConfigSource(c ConfigSource) { n.configs = c }

func (n *Node) HealthyWithin() time.Duration {
	interval := n.cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return interval * healthyIntervals
}

func (n *Node) Run(ctx context.Context) {
	if !n.Enabled() {
		return
	}
	n.log.Info("clustering enabled",
		"node_id", n.id, "role", n.Role(), "peers", len(n.peers()),
		"advertise_url", n.cfg.AdvertiseURL, "sync_config", n.cfg.SyncConfig)

	if n.cfg.AdvertiseURL == "" && len(n.cfg.Peers) > 0 {
		n.log.Warn("cluster.advertise_url is empty, so peers will list this node without an address")
	}

	interval := n.cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	n.round(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.round(ctx)
		}
	}
}

func (n *Node) round(ctx context.Context) {
	self, err := n.Snapshot(ctx)
	if err != nil {
		n.log.Error("cluster: could not describe this node", "error", err)
		return
	}

	if err := n.db.UpsertNode(ctx, heartbeatToNode(self)); err != nil {
		n.log.Error("cluster: could not record this node", "error", err)
	}

	var wg sync.WaitGroup
	for _, peer := range n.peers() {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			n.greet(ctx, peer, self)
		}(peer)
	}
	wg.Wait()

	n.syncConfig(ctx, self)

	if cut, err := n.db.ForgetStaleNodes(ctx, time.Now().UTC().Add(-forgetAfter)); err != nil {
		n.log.Warn("cluster: could not forget stale nodes", "error", err)
	} else if cut > 0 {
		n.log.Info("cluster: forgot nodes that have been silent for a week", "nodes", cut)
	}
}

func (n *Node) Snapshot(ctx context.Context) (*Heartbeat, error) {
	stats, err := n.db.Stats(ctx)
	if err != nil {
		return nil, fmt.Errorf("read queue stats: %w", err)
	}
	domains, err := n.db.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("read domains: %w", err)
	}

	hash := ""
	if n.configs != nil {
		if hash, err = n.configs.ConfigHash(ctx); err != nil {
			n.log.Warn("cluster: could not fingerprint the configuration", "error", err)
			hash = ""
		}
	}

	return &Heartbeat{
		NodeID:       n.id,
		AdvertiseURL: n.cfg.AdvertiseURL,
		Version:      n.version,
		Role:         n.Role(),
		ConfigHash:   hash,
		QueuePending: stats.Pending,
		QueueBytes:   stats.PendingBytes,
		Domains:      int64(len(domains)),
		At:           time.Now().UTC(),
	}, nil
}

func (n *Node) Observe(ctx context.Context, hb *Heartbeat) error {
	return n.db.UpsertNode(ctx, heartbeatToNode(hb))
}

func heartbeatToNode(hb *Heartbeat) *store.Node {
	return &store.Node{
		ID:           hb.NodeID,
		AdvertiseURL: hb.AdvertiseURL,
		Version:      hb.Version,
		Role:         hb.Role,
		ConfigHash:   hb.ConfigHash,
		QueuePending: hb.QueuePending,
		QueueBytes:   hb.QueueBytes,
		Domains:      hb.Domains,
	}
}

func (n *Node) peers() []string {
	mine := strings.TrimRight(n.cfg.AdvertiseURL, "/")
	out := make([]string, 0, len(n.cfg.Peers))
	for _, peer := range n.cfg.Peers {
		if mine != "" && strings.EqualFold(strings.TrimRight(peer, "/"), mine) {
			continue
		}
		out = append(out, peer)
	}
	return out
}

func (n *Node) greet(ctx context.Context, peer string, self *Heartbeat) {
	body, err := json.Marshal(self)
	if err != nil {
		n.log.Error("cluster: could not encode the heartbeat", "error", err)
		return
	}

	var theirs Heartbeat
	if err := n.call(ctx, http.MethodPost, peer, HeartbeatPath, body, &theirs); err != nil {
		n.log.Warn("cluster: a peer did not answer", "peer", peer, "error", err)
		return
	}
	if theirs.NodeID == "" || theirs.NodeID == n.id {
		n.log.Warn("cluster: a peer identified itself as this node; check cluster.node_id",
			"peer", peer, "node_id", theirs.NodeID)
		return
	}
	if err := n.db.UpsertNode(ctx, heartbeatToNode(&theirs)); err != nil {
		n.log.Error("cluster: could not record a peer", "peer", theirs.NodeID, "error", err)
		return
	}
	n.log.Debug("peer seen", "peer", theirs.NodeID, "role", theirs.Role,
		"pending", theirs.QueuePending, "config", theirs.ConfigHash)
}

func (n *Node) syncConfig(ctx context.Context, self *Heartbeat) {
	if !n.cfg.SyncConfig || n.Role() != store.NodeFollower || n.configs == nil {
		return
	}
	if self.ConfigHash == "" {
		return
	}

	nodes, err := n.db.ListNodes(ctx)
	if err != nil {
		n.log.Warn("cluster: could not read the peer list", "error", err)
		return
	}

	var primary *store.Node
	for _, node := range nodes {
		if node.ID == n.id || node.Role != store.NodePrimary || node.AdvertiseURL == "" {
			continue
		}
		if !node.Healthy(time.Now().UTC(), n.HealthyWithin()) {
			continue
		}
		if primary != nil {
			n.log.Error("cluster: more than one node claims the primary role, not syncing",
				"first", primary.ID, "second", node.ID)
			return
		}
		primary = node
	}
	if primary == nil || primary.ConfigHash == "" || primary.ConfigHash == self.ConfigHash {
		return
	}

	n.log.Info("cluster: configuration differs from the primary, pulling",
		"primary", primary.ID, "theirs", primary.ConfigHash, "ours", self.ConfigHash)

	var doc struct {
		YAML string `json:"yaml"`
	}
	if err := n.call(ctx, http.MethodGet, primary.AdvertiseURL, ConfigPath, nil, &doc); err != nil {
		n.log.Error("cluster: could not fetch the primary's configuration",
			"primary", primary.ID, "error", err)
		return
	}

	report, err := n.configs.ApplyConfigYAML(ctx, []byte(doc.YAML), false)
	if err != nil {
		n.log.Error("cluster: the primary's configuration would not apply",
			"primary", primary.ID, "error", err)
		return
	}

	summary, _ := report["description"].(string)
	changed, _ := report["changed"].(int)
	if changed == 0 {
		n.log.Warn("cluster: config pulled but nothing changed; the nodes will keep reporting different hashes",
			"primary", primary.ID, "summary", summary)
		return
	}
	n.log.Warn("cluster: configuration pulled from the primary",
		"primary", primary.ID, "summary", summary)

	if err := n.db.RecordEvent(ctx, &store.Event{
		Type: "cluster_config_synced",
		Data: map[string]any{"primary": primary.ID, "summary": summary},
	}); err != nil {
		n.log.Warn("cluster: sync event not recorded", "error", err)
	}
}

func (n *Node) call(ctx context.Context, method, base, path string, body []byte, out any) error {
	url := strings.TrimRight(base, "/") + path

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "XeronMX")
	SignRequest(req, n.cfg.Secret, n.id, body)

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s answered %d: %s", url, resp.StatusCode,
			strings.TrimSpace(truncate(string(raw), 200)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s returned something that is not the expected JSON: %w", url, err)
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
