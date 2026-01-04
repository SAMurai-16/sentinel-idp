package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

type JWKSHandler struct {
	KeyManager *KeyManager
}


func bigIntToBase64(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}


func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if h.KeyManager == nil || h.KeyManager.publicKeys == nil {
		http.Error(w, "jwks not initialized", http.StatusInternalServerError)
		return
	}

	var keys []map[string]interface{}
	

	for kid, pub := range h.KeyManager.publicKeys {
		e := big.NewInt(0).SetInt64(int64(pub.E))
		keys = append(keys, map[string]interface{}{
			"kty": "RSA",
			"kid": kid,
			"alg": "RS256",
			"use": "sig",
			"n":   bigIntToBase64(pub.N),
			"e":   bigIntToBase64(e),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}
