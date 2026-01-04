package jwtutil

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"

)

type Loader struct {

	DB *sql.DB

}




func ParseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}

	// Try PKCS#1 first
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	return key, nil
}



func ParseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}

	// Try PKIX
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return pub, nil
}





func LoadKeys(db *sql.DB) (*KeyManager, error) {
	rows, err := db.Query(`
		SELECT kid, private_key_pem, public_key_pem, active
		FROM signing_keys
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	km := &KeyManager{
		privateKeys: make(map[string]*rsa.PrivateKey),
		publicKeys:  make(map[string]*rsa.PublicKey),
	}

	for rows.Next() {
		var kid, privPEM, pubPEM string
		var active bool

		if err := rows.Scan(&kid, &privPEM, &pubPEM, &active); err != nil {
			return nil, err
		}

		privKey, err := ParseRSAPrivateKey(privPEM)
		if err != nil {
			return nil, fmt.Errorf("private key parse failed (kid=%s): %w", kid, err)
		}

		pubKey, err := ParseRSAPublicKey(pubPEM)
		if err != nil {
			return nil, fmt.Errorf("public key parse failed (kid=%s): %w", kid, err)
		}

		// Sanity check: keys must match
		if privKey.PublicKey.N.Cmp(pubKey.N) != 0 {
			return nil, fmt.Errorf("key mismatch for kid=%s", kid)
		}

		km.privateKeys[kid] = privKey
		km.publicKeys[kid] = pubKey

		if active {
			km.activeKID = kid
		}

		log.Printf("loaded signing key kid=%s active=%v", kid, active)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if km.activeKID == "" {
		return nil, errors.New("no active signing key")
	}

	return km, nil
}
