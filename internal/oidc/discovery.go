package oidc

import (
	"encoding/json"
	"net/http"
)

func DiscoveryHandler(issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		doc := map[string]interface{}{
			"issuer": issuer,

			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",

			"response_types_supported": []string{
				"code",
			},

			"grant_types_supported": []string{
				"authorization_code",
				"refresh_token",
			},

			"subject_types_supported": []string{
				"public",
			},

			"id_token_signing_alg_values_supported": []string{
				"RS256",
			},

			"scopes_supported": []string{
				"read:profile",
				"read:data",
				"write:data",
				"admin:users",
			},

			"token_endpoint_auth_methods_supported": []string{
				"none",
			},

			"code_challenge_methods_supported": []string{
				"S256",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}
}
