package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type User struct {
	ID             int64
	Email          string
	PasswordHash   string
	Role           string
	AllowedDomains []string
	CreatedAt      time.Time
	LastLoginAt    *time.Time

	OIDCIssuer  string
	OIDCSubject string

	TOTPSecret   string
	TOTPEnabled  bool
	TOTPLastStep int64
}

func (u *User) Scoped() bool {
	return u.Role != RoleAdmin && len(u.AllowedDomains) > 0
}

func (u *User) CanAccessDomain(domainName string) bool {
	if !u.Scoped() {
		return true
	}
	for _, d := range u.AllowedDomains {
		if strings.EqualFold(d, domainName) {
			return true
		}
	}
	return false
}

func (u *User) CanAccessDomainID(ctx context.Context, db *DB, domainID int64) (bool, error) {
	if !u.Scoped() {
		return true, nil
	}
	d, err := db.DomainByID(ctx, domainID)
	if err != nil {
		return false, err
	}
	return u.CanAccessDomain(d.Name), nil
}

func (u *User) FromDirectory() bool { return u.OIDCSubject != "" }

func (u *User) HasPassword() bool { return u.PasswordHash != "" }

const (
	RoleAdmin = "admin"

	RoleOperator = "operator"

	RoleViewer = "viewer"
)

func (db *DB) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

func (db *DB) CreateUser(ctx context.Context, email, passwordHash, role string, allowedDomains ...[]string) (int64, error) {
	domains := []string{}
	if len(allowedDomains) > 0 && allowedDomains[0] != nil {
		domains = allowedDomains[0]
	}
	raw, err := json.Marshal(domains)
	if err != nil {
		return 0, fmt.Errorf("store: marshal allowed domains: %w", err)
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO users (email, password_hash, role, allowed_domains, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		normalizeEmail(email), passwordHash, role, string(raw), formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: create user: %w", err)
	}
	return res.LastInsertId()
}

var ErrAlreadySetUp = errors.New("store: this instance already has an account")

var ErrLastAdmin = errors.New("store: cannot remove or demote the last administrator")

func (db *DB) CreateFirstUser(ctx context.Context, email, passwordHash, role string) (int64, error) {
	res, err := db.ExecContext(ctx, `
		INSERT INTO users (email, password_hash, role, allowed_domains, created_at)
		SELECT ?, ?, ?, '[]', ?
		WHERE NOT EXISTS (SELECT 1 FROM users)`,
		normalizeEmail(email), passwordHash, role, formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: create first user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: rows affected: %w", err)
	}
	if n == 0 {
		return 0, ErrAlreadySetUp
	}
	return res.LastInsertId()
}

func (db *DB) UserByEmail(ctx context.Context, email string) (*User, error) {
	return db.scanUser(db.QueryRowContext(ctx, userCols+` WHERE email = ?`, normalizeEmail(email)))
}

func (db *DB) UserByID(ctx context.Context, id int64) (*User, error) {
	return db.scanUser(db.QueryRowContext(ctx, userCols+` WHERE id = ?`, id))
}

func (db *DB) TouchLogin(ctx context.Context, id int64) error {
	return db.exec(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`,
		formatTime(time.Now().UTC()), id)
}

func (db *DB) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := db.QueryContext(ctx, userCols+` ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u, err := db.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (db *DB) CountAdminUsers(ctx context.Context) (int64, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, RoleAdmin).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count admin users: %w", err)
	}
	return n, nil
}

func (db *DB) UpdateUserRole(ctx context.Context, id int64, newRole string) error {
	u, err := db.UserByID(ctx, id)
	if err != nil {
		return err
	}
	return db.UpdateUserScope(ctx, id, newRole, u.AllowedDomains)
}

func (db *DB) UpdateUserScope(ctx context.Context, id int64, newRole string, allowedDomains []string) error {
	u, err := db.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin && newRole != RoleAdmin {
		admins, err := db.CountAdminUsers(ctx)
		if err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if allowedDomains == nil {
		allowedDomains = []string{}
	}
	raw, err := json.Marshal(allowedDomains)
	if err != nil {
		return fmt.Errorf("store: marshal allowed domains: %w", err)
	}
	return db.exec(ctx, `UPDATE users SET role = ?, allowed_domains = ? WHERE id = ?`, newRole, string(raw), id)
}

func (db *DB) DeleteUser(ctx context.Context, id int64) error {
	u, err := db.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin {
		admins, err := db.CountAdminUsers(ctx)
		if err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if err := db.DeleteUserSessions(ctx, id); err != nil {
		return err
	}
	return db.exec(ctx, `DELETE FROM users WHERE id = ?`, id)
}

const userCols = `
	SELECT id, email, password_hash, role, allowed_domains, created_at, last_login_at, oidc_issuer, oidc_subject,
	       totp_secret, totp_enabled, totp_last_step
	FROM users`

func (db *DB) scanUser(row rowScanner) (*User, error) {
	var (
		u              User
		allowedDomains string
		created        string
		lastLogin      sql.NullString
		issuer         sql.NullString
		subject        sql.NullString
	)
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &allowedDomains, &created, &lastLogin,
		&issuer, &subject, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastStep)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan user: %w", err)
	}
	if err := json.Unmarshal([]byte(allowedDomains), &u.AllowedDomains); err != nil {
		u.AllowedDomains = []string{}
	}
	if u.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if u.LastLoginAt, err = nullTime(lastLogin); err != nil {
		return nil, err
	}
	u.OIDCIssuer = issuer.String
	u.OIDCSubject = subject.String
	return &u, nil
}

func (db *DB) CreateSession(ctx context.Context, tokenHash string, userID int64, ttl time.Duration, userAgent string) error {
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, expires_at, user_agent)
		VALUES (?, ?, ?, ?, ?)`,
		tokenHash, userID, formatTime(now), formatTime(now.Add(ttl)), truncate(userAgent, 300))
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

func (db *DB) UserBySessionToken(ctx context.Context, tokenHash string) (*User, error) {
	return db.scanUser(db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.password_hash, u.role, u.allowed_domains, u.created_at, u.last_login_at,
		       u.oidc_issuer, u.oidc_subject, u.totp_secret, u.totp_enabled, u.totp_last_step
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`,
		tokenHash, formatTime(time.Now().UTC())))
}

func (db *DB) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

func (db *DB) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("store: delete user sessions: %w", err)
	}
	return nil
}

func (db *DB) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`,
		formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: purge sessions: %w", err)
	}
	return res.RowsAffected()
}

func normalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

type SMTPUser struct {
	ID             int64
	Username       string
	PasswordHash   string
	AllowedDomains []string
	Enabled        bool
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

func (u *SMTPUser) MaySend(from string) bool {
	if !u.Enabled {
		return false
	}
	if len(u.AllowedDomains) == 0 {
		return true
	}

	if from == "" {
		return true
	}
	at := strings.LastIndex(from, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(from[at+1:])
	for _, allowed := range u.AllowedDomains {
		if strings.EqualFold(allowed, domain) {
			return true
		}
	}
	return false
}

func (db *DB) CreateSMTPUser(ctx context.Context, username, passwordHash string, allowedDomains []string) (int64, error) {
	if allowedDomains == nil {
		allowedDomains = []string{}
	}
	raw, err := json.Marshal(allowedDomains)
	if err != nil {
		return 0, fmt.Errorf("store: marshal allowed domains: %w", err)
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO smtp_users (username, password_hash, allowed_domains, enabled, created_at)
		VALUES (?, ?, ?, 1, ?)`,
		strings.TrimSpace(username), passwordHash, string(raw), formatTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: create smtp user: %w", err)
	}
	return res.LastInsertId()
}

func (db *DB) SMTPUserByName(ctx context.Context, username string) (*SMTPUser, error) {
	return db.scanSMTPUser(db.QueryRowContext(ctx, smtpUserCols+` WHERE username = ?`,
		strings.TrimSpace(username)))
}

func (db *DB) ListSMTPUsers(ctx context.Context) ([]*SMTPUser, error) {
	rows, err := db.QueryContext(ctx, smtpUserCols+` ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: list smtp users: %w", err)
	}
	defer rows.Close()

	var out []*SMTPUser
	for rows.Next() {
		u, err := scanSMTPUserRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (db *DB) DeleteSMTPUser(ctx context.Context, id int64) error {
	return db.exec(ctx, `DELETE FROM smtp_users WHERE id = ?`, id)
}

func (db *DB) SetSMTPUserEnabled(ctx context.Context, id int64, enabled bool) error {
	return db.exec(ctx, `UPDATE smtp_users SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
}

func (db *DB) TouchSMTPUser(ctx context.Context, id int64) error {
	return db.exec(ctx, `UPDATE smtp_users SET last_used_at = ? WHERE id = ?`,
		formatTime(time.Now().UTC()), id)
}

const smtpUserCols = `
	SELECT id, username, password_hash, allowed_domains, enabled, created_at, last_used_at
	FROM smtp_users`

func (db *DB) scanSMTPUser(row rowScanner) (*SMTPUser, error) {
	u, err := scanSMTPUserRow(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func scanSMTPUserRow(row rowScanner) (*SMTPUser, error) {
	var (
		u        SMTPUser
		domains  string
		enabled  int
		created  string
		lastUsed sql.NullString
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &domains, &enabled, &created, &lastUsed)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan smtp user: %w", err)
	}
	if err := json.Unmarshal([]byte(domains), &u.AllowedDomains); err != nil {
		u.AllowedDomains = nil
	}
	u.Enabled = enabled != 0
	if u.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if u.LastUsedAt, err = nullTime(lastUsed); err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) UserByOIDC(ctx context.Context, issuer, subject string) (*User, error) {
	return db.scanUser(db.QueryRowContext(ctx,
		userCols+` WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, subject))
}

func (db *DB) LinkOIDC(ctx context.Context, userID int64, issuer, subject string) error {
	return db.exec(ctx, `UPDATE users SET oidc_issuer = ?, oidc_subject = ? WHERE id = ?`,
		issuer, subject, userID)
}

func (db *DB) CreateOIDCUser(ctx context.Context, email, role, issuer, subject string, allowedDomains ...[]string) (int64, error) {
	domains := []string{}
	if len(allowedDomains) > 0 && allowedDomains[0] != nil {
		domains = allowedDomains[0]
	}
	raw, err := json.Marshal(domains)
	if err != nil {
		return 0, fmt.Errorf("store: marshal allowed domains: %w", err)
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO users (email, password_hash, role, allowed_domains, created_at, oidc_issuer, oidc_subject)
		VALUES (?, '', ?, ?, ?, ?, ?)`,
		normalizeEmail(email), role, string(raw), formatTime(time.Now().UTC()), issuer, subject)
	if err != nil {
		return 0, fmt.Errorf("store: create oidc user: %w", err)
	}
	return res.LastInsertId()
}
