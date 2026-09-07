package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	NodePrimary  = "primary"
	NodeFollower = "follower"
)

type Node struct {
	ID           string
	AdvertiseURL string
	Version      string
	Role         string
	ConfigHash   string
	QueuePending int64
	QueueBytes   int64
	Domains      int64
	FirstSeen    time.Time
	LastSeen     time.Time
}

func (n *Node) Healthy(now time.Time, within time.Duration) bool {
	return now.Sub(n.LastSeen) <= within
}

func (db *DB) UpsertNode(ctx context.Context, n *Node) error {
	now := formatTime(time.Now().UTC())
	role := n.Role
	if role != NodePrimary {
		role = NodeFollower
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO cluster_nodes
			(node_id, advertise_url, version, role, config_hash,
			 queue_pending, queue_bytes, domains, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			advertise_url = excluded.advertise_url,
			version       = excluded.version,
			role          = excluded.role,
			config_hash   = excluded.config_hash,
			queue_pending = excluded.queue_pending,
			queue_bytes   = excluded.queue_bytes,
			domains       = excluded.domains,
			last_seen     = excluded.last_seen`,
		strings.TrimSpace(n.ID), n.AdvertiseURL, n.Version, role, n.ConfigHash,
		n.QueuePending, n.QueueBytes, n.Domains, now, now)
	if err != nil {
		return fmt.Errorf("store: upsert node: %w", err)
	}
	return nil
}

func (db *DB) ListNodes(ctx context.Context) ([]*Node, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT node_id, advertise_url, version, role, config_hash,
		       queue_pending, queue_bytes, domains, first_seen, last_seen
		FROM cluster_nodes ORDER BY node_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer rows.Close()

	var out []*Node
	for rows.Next() {
		var (
			n     Node
			first string
			last  string
		)
		if err := rows.Scan(&n.ID, &n.AdvertiseURL, &n.Version, &n.Role, &n.ConfigHash,
			&n.QueuePending, &n.QueueBytes, &n.Domains, &first, &last); err != nil {
			return nil, fmt.Errorf("store: scan node: %w", err)
		}
		var err error
		if n.FirstSeen, err = parseTime(first); err != nil {
			return nil, err
		}
		if n.LastSeen, err = parseTime(last); err != nil {
			return nil, err
		}
		out = append(out, &n)
	}
	return out, rows.Err()
}

func (db *DB) DeleteNode(ctx context.Context, id string) error {
	return db.exec(ctx, `DELETE FROM cluster_nodes WHERE node_id = ?`, id)
}

func (db *DB) ForgetStaleNodes(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM cluster_nodes WHERE last_seen < ?`,
		formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: forget stale nodes: %w", err)
	}
	return res.RowsAffected()
}
