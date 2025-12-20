package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func VerifyPKCE(verifier, challenge string) error {
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	if computed != challenge {
		return errors.New("pkce verification failed")
	}
	return nil
}
