package oauth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type AuthCode struct {
	Code          string
	ClientID      string
	UserID        int
	CodeChallenge string
	ExpiresAt     time.Time
}

var ErrInvalidCode = errors.New("invalid or expired authorization code")

func ConsumeAuthCode(
	ctx context.Context,
	tx *sql.Tx,
	code string,
) (*AuthCode, error) {

	var ac AuthCode

	err := tx.QueryRowContext(ctx, `
		SELECT code, client_id, user_id, code_challenge, expires_at
		FROM authorization_codes
		WHERE code = $1
	`, code).Scan(
		&ac.Code,
		&ac.ClientID,
		&ac.UserID,
		&ac.CodeChallenge,
		&ac.ExpiresAt,
	)

	if err != nil {
		return nil, ErrInvalidCode
	}

	if time.Now().After(ac.ExpiresAt) {
		return nil, ErrInvalidCode
	}

	// 🔥 SINGLE-USE: delete immediately
	_, err = tx.ExecContext(ctx,
		`DELETE FROM authorization_codes WHERE code = $1`,
		code,
	)
	if err != nil {
		return nil, err
	}

	return &ac, nil
}
