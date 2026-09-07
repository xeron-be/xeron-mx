package store

import (
	"context"
	"fmt"
	"time"
)

type QueueBreakdown struct {
	DomainID   int64
	DomainName string
	Status     Status
	Count      int64
	Bytes      int64
}

func (db *DB) Breakdown(ctx context.Context) ([]QueueBreakdown, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT q.domain_id, d.name, q.status, COUNT(*), COALESCE(SUM(q.size_bytes), 0)
		FROM queue q
		JOIN domains d ON d.id = q.domain_id
		GROUP BY q.domain_id, q.status
		ORDER BY d.name, q.status`)
	if err != nil {
		return nil, fmt.Errorf("store: breakdown: %w", err)
	}
	defer rows.Close()

	var out []QueueBreakdown
	for rows.Next() {
		var b QueueBreakdown
		var status string
		if err := rows.Scan(&b.DomainID, &b.DomainName, &status, &b.Count, &b.Bytes); err != nil {
			return nil, fmt.Errorf("store: scan breakdown: %w", err)
		}
		b.Status = Status(status)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (db *DB) OldestQueued(ctx context.Context) (time.Duration, error) {
	var received string
	err := db.QueryRowContext(ctx, `
		SELECT received_at FROM queue
		WHERE status IN ('queued','delivering')
		ORDER BY received_at LIMIT 1`).Scan(&received)
	if err != nil {

		return 0, nil
	}
	t, err := parseTime(received)
	if err != nil {
		return 0, err
	}
	return time.Since(t), nil
}

type DomainHealth struct {
	Domain *Domain
	Status *PrimaryStatus
}

func (db *DB) AllDomainHealth(ctx context.Context) ([]DomainHealth, error) {
	domains, err := db.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DomainHealth, 0, len(domains))
	for _, d := range domains {
		dh := DomainHealth{Domain: d}
		if st, err := db.PrimaryStatusFor(ctx, d.ID); err == nil {
			dh.Status = st
		}
		out = append(out, dh)
	}
	return out, nil
}
