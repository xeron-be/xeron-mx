package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	AlgorithmRSA     = "rsa"
	AlgorithmEd25519 = "ed25519"
)

type DKIMKey struct {
	DomainID   int64
	Selector   string
	Algorithm  string
	PrivateKey []byte
	PublicKey  string
	Enabled    bool
	CreatedAt  time.Time
}

func ValidDKIMAlgorithm(a string) bool {
	return a == AlgorithmRSA || a == AlgorithmEd25519
}

func (db *DB) SaveDKIMKey(ctx context.Context, k *DKIMKey) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO dkim_keys (domain_id, selector, algorithm, private_key, public_key, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain_id) DO UPDATE SET
			selector = excluded.selector,
			algorithm = excluded.algorithm,
			private_key = excluded.private_key,
			public_key = excluded.public_key,
			enabled = excluded.enabled`,
		k.DomainID, strings.TrimSpace(k.Selector), k.Algorithm,
		k.PrivateKey, k.PublicKey, boolToInt(k.Enabled), formatTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("store: save dkim key: %w", err)
	}
	return nil
}

func (db *DB) DKIMKeyFor(ctx context.Context, domainID int64) (*DKIMKey, error) {
	var (
		k       DKIMKey
		enabled int
		created string
	)
	err := db.QueryRowContext(ctx, `
		SELECT domain_id, selector, algorithm, private_key, public_key, enabled, created_at
		FROM dkim_keys WHERE domain_id = ?`, domainID).
		Scan(&k.DomainID, &k.Selector, &k.Algorithm, &k.PrivateKey, &k.PublicKey, &enabled, &created)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read dkim key: %w", err)
	}
	k.Enabled = enabled != 0
	if k.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	return &k, nil
}

func (db *DB) SetDKIMEnabled(ctx context.Context, domainID int64, enabled bool) error {
	return db.exec(ctx, `UPDATE dkim_keys SET enabled = ? WHERE domain_id = ?`,
		boolToInt(enabled), domainID)
}

func (db *DB) DeleteDKIMKey(ctx context.Context, domainID int64) error {
	return db.exec(ctx, `DELETE FROM dkim_keys WHERE domain_id = ?`, domainID)
}

type Route struct {
	ID            int64
	Destination   string
	Mode          string
	RelayHost     string
	RelayPort     int
	RelayTLS      string
	RelayUsername string
	RelayPassword []byte
	Enabled       bool
	CreatedAt     time.Time
}

func (db *DB) CreateRoute(ctx context.Context, r *Route) (int64, error) {
	res, err := db.ExecContext(ctx, `
		INSERT INTO routes (destination, mode, relay_host, relay_port, relay_tls,
		                    relay_username, relay_password, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalizeDestination(r.Destination), r.Mode, r.RelayHost, r.RelayPort, r.RelayTLS,
		r.RelayUsername, r.RelayPassword, boolToInt(r.Enabled), formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: create route: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) UpdateRoute(ctx context.Context, r *Route) error {
	return db.exec(ctx, `
		UPDATE routes
		SET destination = ?, mode = ?, relay_host = ?, relay_port = ?, relay_tls = ?,
		    relay_username = ?, relay_password = ?, enabled = ?
		WHERE id = ?`,
		normalizeDestination(r.Destination), r.Mode, r.RelayHost, r.RelayPort, r.RelayTLS,
		r.RelayUsername, r.RelayPassword, boolToInt(r.Enabled), r.ID)
}

func (db *DB) DeleteRoute(ctx context.Context, id int64) error {
	return db.exec(ctx, `DELETE FROM routes WHERE id = ?`, id)
}

func (db *DB) RouteByID(ctx context.Context, id int64) (*Route, error) {
	return db.scanRoute(db.QueryRowContext(ctx, routeCols+` WHERE id = ?`, id))
}

func (db *DB) ListRoutes(ctx context.Context) ([]*Route, error) {
	rows, err := db.QueryContext(ctx, routeCols+` ORDER BY destination`)
	if err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	defer rows.Close()

	var out []*Route
	for rows.Next() {
		r, err := scanRouteRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) RouteFor(ctx context.Context, destination string) (*Route, error) {
	routes, err := db.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}

	dest := normalizeDestination(destination)
	var best *Route
	for _, r := range routes {
		if !r.Enabled || !routeMatches(r.Destination, dest) {
			continue
		}
		if best == nil || len(r.Destination) > len(best.Destination) {
			best = r
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return best, nil
}

func routeMatches(pattern, dest string) bool {
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(dest, pattern)
	}
	return pattern == dest
}

func normalizeDestination(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

const routeCols = `
	SELECT id, destination, mode, relay_host, relay_port, relay_tls,
	       relay_username, relay_password, enabled, created_at
	FROM routes`

func (db *DB) scanRoute(row rowScanner) (*Route, error) {
	r, err := scanRouteRow(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return r, err
}

func scanRouteRow(row rowScanner) (*Route, error) {
	var (
		r        Route
		password []byte
		enabled  int
		created  string
	)
	err := row.Scan(&r.ID, &r.Destination, &r.Mode, &r.RelayHost, &r.RelayPort,
		&r.RelayTLS, &r.RelayUsername, &password, &enabled, &created)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan route: %w", err)
	}
	r.RelayPassword = password
	r.Enabled = enabled != 0
	if r.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	return &r, nil
}
