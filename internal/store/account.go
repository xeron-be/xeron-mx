package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (db *DB) UpdatePassword(ctx context.Context, userID int64, hash string) error {
	res, err := db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
	if err != nil {
		return fmt.Errorf("store: update password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) DeleteOtherSessions(ctx context.Context, userID int64, keepTokenHash string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`,
		userID, keepTokenHash)
	if err != nil {
		return fmt.Errorf("store: delete other sessions: %w", err)
	}
	return nil
}

func (db *DB) SetPendingTOTP(ctx context.Context, userID int64, sealedSecret string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE users SET totp_secret = ?, totp_last_step = 0
		WHERE id = ? AND totp_enabled = 0`, sealedSecret, userID)
	if err != nil {
		return fmt.Errorf("store: set pending totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) EnableTOTP(ctx context.Context, userID, step int64, recoveryHashes []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: enable totp: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		UPDATE users SET totp_enabled = 1, totp_last_step = ?
		WHERE id = ? AND totp_enabled = 0 AND totp_secret <> ''`, step, userID)
	if err != nil {
		return fmt.Errorf("store: enable totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := replaceRecoveryCodes(ctx, tx, userID, recoveryHashes); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) ConsumeTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE users SET totp_last_step = ?
		WHERE id = ? AND totp_enabled = 1 AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, fmt.Errorf("store: consume totp step: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (db *DB) ConsumeRecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE totp_recovery_codes SET used_at = ?
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
		formatTime(time.Now().UTC()), userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("store: consume recovery code: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (db *DB) RecoveryCodesLeft(ctx context.Context, userID int64) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count recovery codes: %w", err)
	}
	return n, nil
}

func (db *DB) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: replace recovery codes: %w", err)
	}
	defer tx.Rollback()
	if err := replaceRecoveryCodes(ctx, tx, userID, hashes); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, userID int64, hashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: replace recovery codes: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return fmt.Errorf("store: replace recovery codes: %w", err)
		}
	}
	return nil
}

func (db *DB) DisableTOTP(ctx context.Context, userID int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: disable totp: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET totp_secret = '', totp_enabled = 0, totp_last_step = 0 WHERE id = ?`, userID); err != nil {
		return fmt.Errorf("store: disable totp: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: disable totp: %w", err)
	}
	return tx.Commit()
}
