package jwtutil

import (
	"crypto/rsa"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
	Issuer     string
	DB *sql.DB
}


func getScopesForUser(db *sql.DB, userID int) ([]string, error) {
	rows, err := db.Query(`
		SELECT s.name
		FROM scopes s
		JOIN role_scopes rs ON rs.scope_id = s.id
		JOIN users u ON u.role_id = rs.role_id
		WHERE u.id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		scopes = append(scopes, s)
	}
	return scopes, nil
}


func (s *Signer) MintAccessToken(userID int, clientID string) (string, error) {
	now := time.Now()

	scopes, _ := getScopesForUser(s.DB, userID)

	claims := jwt.MapClaims{
		"iss": s.Issuer,
		"sub": userID,
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
		"jti": uuid.NewString(),
		"scope": strings.Join(scopes, " "),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.KeyID

	return token.SignedString(s.PrivateKey)
}



func (s *Signer) MintIDToken(userID int, clientID string, authTime time.Time) (string, error) {

	var username string
	err := s.DB.QueryRow(
		`SELECT username FROM users WHERE id=$1`,
		userID,
	).Scan(&username)
	if err != nil {
		return "", err
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       s.Issuer,
		"sub":       userID,
		"aud":       clientID,
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),

		"preferred_username": username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.PrivateKey)
}
