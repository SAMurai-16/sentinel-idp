package jwtutil

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
	Issuer     string
}

func (s *Signer) MintAccessToken(userID int, clientID string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss": s.Issuer,
		"sub": userID,
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.KeyID

	return token.SignedString(s.PrivateKey)
}
