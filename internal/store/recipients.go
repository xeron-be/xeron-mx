package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

func NormalizeRecipient(addr string) string {
	return strings.ToLower(strings.TrimSpace(addr))
}

func (db *DB) DomainRecipients(ctx context.Context, domainID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT address FROM domain_recipients WHERE domain_id = ? ORDER BY address`, domainID)
	if err != nil {
		return nil, fmt.Errorf("store: list recipients: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, rows.Err()
}

func (db *DB) SetDomainRecipients(ctx context.Context, domainID int64, addrs []string) error {
	clean := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a = NormalizeRecipient(a); a != "" {
			clean = append(clean, a)
		}
	}
	slices.Sort(clean)
	clean = slices.Compact(clean)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin set recipients: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_recipients WHERE domain_id = ?`, domainID); err != nil {
		return fmt.Errorf("store: clear recipients: %w", err)
	}
	for _, a := range clean {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO domain_recipients (domain_id, address) VALUES (?, ?)`, domainID, a); err != nil {
			return fmt.Errorf("store: add recipient %s: %w", a, err)
		}
	}
	return tx.Commit()
}

func (db *DB) RecipientAllowed(ctx context.Context, domainID int64, addr string) (bool, error) {
	var listed, match int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(address = ?), 0)
		FROM domain_recipients WHERE domain_id = ?`,
		NormalizeRecipient(addr), domainID).Scan(&listed, &match)
	if err != nil {
		return false, fmt.Errorf("store: check recipient: %w", err)
	}
	return listed == 0 || match > 0, nil
}
