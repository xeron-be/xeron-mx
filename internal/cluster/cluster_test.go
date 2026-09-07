package cluster

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func newNode(t *testing.T, cfg config.ClusterConfig, id, role string) (*Node, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, id, role, "test", db, log), db
}

func TestPeersExcludesThisNode(t *testing.T) {
	cfg := config.ClusterConfig{
		Enabled:      true,
		AdvertiseURL: "http://mx-1.svc:8080",
		Peers: []string{
			"http://mx-0.svc:8080",
			"http://mx-1.svc:8080",
			"http://mx-2.svc:8080/",
		},
	}
	n, _ := newNode(t, cfg, "mx-1", store.NodeFollower)

	got := n.peers()
	if len(got) != 2 {
		t.Fatalf("peers() = %v, want the two that are not this node", got)
	}
	for _, p := range got {
		if p == cfg.AdvertiseURL {
			t.Fatal("this node is still in its own peer list")
		}
	}
}

func TestPeersToleratesATrailingSlash(t *testing.T) {
	cfg := config.ClusterConfig{
		AdvertiseURL: "http://mx-1.svc:8080/",
		Peers:        []string{"http://mx-1.svc:8080", "http://mx-2.svc:8080"},
	}
	n, _ := newNode(t, cfg, "mx-1", store.NodeFollower)
	if got := n.peers(); len(got) != 1 || got[0] != "http://mx-2.svc:8080" {
		t.Fatalf("peers() = %v; a trailing slash made a node gossip with itself", got)
	}
}

func TestPeersKeepsEverythingWithoutAnAdvertiseURL(t *testing.T) {
	cfg := config.ClusterConfig{Peers: []string{"http://a:8080", "http://b:8080"}}
	n, _ := newNode(t, cfg, "mx-1", store.NodeFollower)
	if got := n.peers(); len(got) != 2 {
		t.Fatalf("peers() = %v, want both when this node advertises no address", got)
	}
}

func TestSnapshotDescribesTheNode(t *testing.T) {
	cfg := config.ClusterConfig{Enabled: true, AdvertiseURL: "http://mx-0:8080"}
	n, db := newNode(t, cfg, "mx-0", store.NodePrimary)

	if _, err := db.CreateDomain(context.Background(), &store.Domain{
		Name: "example.test", PrimaryHost: "mail.example.test", PrimaryPort: 25,
		PrimaryTLS: "none", RetentionHours: 168, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	hb, err := n.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if hb.NodeID != "mx-0" || hb.Role != store.NodePrimary {
		t.Fatalf("snapshot identifies the node wrongly: %+v", hb)
	}
	if hb.Domains != 1 {
		t.Errorf("domains = %d, want 1", hb.Domains)
	}
	if hb.AdvertiseURL != "http://mx-0:8080" {
		t.Errorf("advertise_url = %q", hb.AdvertiseURL)
	}
}

func TestSnapshotSurvivesAMissingConfigSource(t *testing.T) {
	n, _ := newNode(t, config.ClusterConfig{Enabled: true}, "mx-0", store.NodeFollower)
	hb, err := n.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if hb.ConfigHash != "" {
		t.Errorf("config_hash = %q, want empty", hb.ConfigHash)
	}
}

func TestObserveRecordsAPeer(t *testing.T) {
	n, db := newNode(t, config.ClusterConfig{Enabled: true}, "mx-0", store.NodePrimary)
	ctx := context.Background()

	if err := n.Observe(ctx, &Heartbeat{
		NodeID: "mx-1", Role: store.NodeFollower, ConfigHash: "abc",
		QueuePending: 3, Domains: 2, AdvertiseURL: "http://mx-1:8080",
	}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	nodes, err := db.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != "mx-1" || nodes[0].QueuePending != 3 {
		t.Fatalf("the peer was not recorded: %+v", nodes)
	}
}

func TestRoundGossipsWithAPeer(t *testing.T) {
	var seen *Heartbeat

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, err := Verify(r, secret, "mx-1", body); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var hb Heartbeat
		if err := json.Unmarshal(body, &hb); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		seen = &hb
		json.NewEncoder(w).Encode(Heartbeat{
			NodeID: "mx-1", Role: store.NodeFollower, ConfigHash: "peerhash",
			QueuePending: 11, At: time.Now().UTC(),
		})
	}))
	defer peer.Close()

	cfg := config.ClusterConfig{
		Enabled: true, Secret: secret, Interval: time.Minute, Timeout: 5 * time.Second,
		AdvertiseURL: "http://mx-0:8080", Peers: []string{peer.URL},
	}
	n, db := newNode(t, cfg, "mx-0", store.NodePrimary)

	n.round(context.Background())

	if seen == nil {
		t.Fatal("the peer never received a heartbeat")
	}
	if seen.NodeID != "mx-0" {
		t.Fatalf("the peer was told this node is %q", seen.NodeID)
	}

	nodes, err := db.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("the fleet has %d nodes after one round, want this node and the peer", len(nodes))
	}
	byID := map[string]*store.Node{}
	for _, node := range nodes {
		byID[node.ID] = node
	}
	if byID["mx-0"] == nil {
		t.Error("a node did not record itself; a fleet of one would show empty")
	}
	if p := byID["mx-1"]; p == nil || p.QueuePending != 11 || p.ConfigHash != "peerhash" {
		t.Fatalf("the peer's answer was not stored: %+v", p)
	}
}

func TestRoundSurvivesAPeerThatRefuses(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer peer.Close()

	cfg := config.ClusterConfig{
		Enabled: true, Secret: secret, Interval: time.Minute, Timeout: 5 * time.Second,
		AdvertiseURL: "http://mx-0:8080", Peers: []string{peer.URL},
	}
	n, db := newNode(t, cfg, "mx-0", store.NodePrimary)

	n.round(context.Background())

	nodes, _ := db.ListNodes(context.Background())
	if len(nodes) != 1 || nodes[0].ID != "mx-0" {
		t.Fatalf("a refusing peer left the fleet as %+v; this node must still be recorded", nodes)
	}
}

func TestHealthyWithinFollowsTheInterval(t *testing.T) {
	n, _ := newNode(t, config.ClusterConfig{Interval: 20 * time.Second}, "mx-0", store.NodeFollower)
	if got := n.HealthyWithin(); got != 60*time.Second {
		t.Fatalf("HealthyWithin = %v, want three intervals", got)
	}

	n, _ = newNode(t, config.ClusterConfig{}, "mx-0", store.NodeFollower)
	if got := n.HealthyWithin(); got != 90*time.Second {
		t.Fatalf("HealthyWithin with no interval = %v, want the default's three intervals", got)
	}
}

func TestRoleIsNormalised(t *testing.T) {
	n, _ := newNode(t, config.ClusterConfig{}, "mx-0", "emperor")
	if n.Role() != store.NodeFollower {
		t.Fatalf("Role() = %q, want follower for anything that is not primary", n.Role())
	}
}
