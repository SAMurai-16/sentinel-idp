package jwtutil

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func bigIntToBase64(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

func PublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	e := big.NewInt(int64(pub.E))

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   bigIntToBase64(pub.N),
		E:   bigIntToBase64(e),
	}
}
