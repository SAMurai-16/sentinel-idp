# Sentinel IDP

An Identity Provider implementing OAuth 2.0 Authorization Code with PKCE, OpenID Connect Discovery, JWT signing (RS256 with `kid`), session-based login, refresh token rotation, token revocation tracking, and JWKS publishing.

## Overview

- Login form creates a session (`sentinel_session`) and protects routes via middleware.
- `/authorize` issues single-use authorization codes (PKCE `S256` required).
- `/token` exchanges codes for `access_token`, `id_token`, and `refresh_token`; supports refresh rotation.
- `/logout` revokes the current access token (by `jti`) and clears cookies (CSRF protected).
- `/.well-known/openid-configuration` serves OIDC discovery.
- `/jwks.json` serves JWKS for public key verification.
- `/revoked?jti=...` checks if an access token `jti` has been revoked.

## Blog

- Read the blog post: https://medium.com/@goforsamyak.c/sentinel-an-identity-provider-with-auth-2-0-and-oidc-framework-0d091f574f3e


## Quick Start

1) Set up database and run migrations

```bash
createdb sentinel
psql -d sentinel -f migrations/001_init.sql
psql -d sentinel -f migrations/002_oauth.sql
psql -d sentinel -f migrations/003_revoke.sql
psql -d sentinel -f migrations/004_refresh_tokens.sql
psql -d sentinel -f migrations/005_rbac.sql
psql -d sentinel -f migrations/006_signing.sql
```

2) Generate an RSA signing key pair and insert into DB

```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Choose a key ID
KID="kid-1"

# Insert into the signing_keys table (adjust psql connection as needed)
psql -d sentinel <<SQL
INSERT INTO signing_keys (kid, private_key_pem, public_key_pem, active)
VALUES ('${KID}', '$(sed "s/'/''/g" private.pem)', '$(sed "s/'/''/g" public.pem)', true);
SQL
```

3) Create a user and OAuth client

Generate a bcrypt password hash (Go one-liner):

```bash
cat > /tmp/hash.go <<'GO'
package main
import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)
func main(){
	h,_ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	fmt.Printf("%s\n", string(h))
}
GO
go run /tmp/hash.go > /tmp/pass.hash
```

Insert user and client:

```bash
psql -d sentinel <<SQL
INSERT INTO users (username, password_hash) VALUES ('alice', '$(cat /tmp/pass.hash)');
INSERT INTO oauth_clients (client_id, redirect_uri) VALUES ('client-123', 'http://localhost:3000/callback');
SQL
```

4) Configure environment and run the server

```bash
export DATABASE_URL="postgres://localhost:5432/sentinel?sslmode=disable"
go run ./cmd/server
```

Server listens on `:8080` with issuer `http://localhost:8080`.

## Endpoints

- Login: `GET/POST /login` → serves `web/templates/login.html`, sets `sentinel_session` cookie.
- Home: `GET /` → requires session, returns "Sentinel running".
- Authorize: `GET /authorize` → requires session; params: `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`.
- Token: `POST /token` → `grant_type=authorization_code|refresh_token`.
- Logout: `POST /logout` → CSRF protected; revokes current `sentinel_access` by `jti`.
- JWKS: `GET /jwks.json` → current public keys and `kid`s.
- OIDC Discovery: `GET /.well-known/openid-configuration` → metadata. Note: implementation returns `jwks_uri` as `${issuer}/jwks`, while the endpoint is `/jwks.json`.
- Revocation Check: `GET /revoked?jti=...` → 200 if revoked, 404 otherwise.

## Authorization Code Flow (PKCE)

1) Login in browser at `https://localhost:8080/login` using the seeded user.
2) Create PKCE values:

```bash
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
```

3) Start authorization request (in browser, due to session requirement):

```
http://localhost:8080/authorize?client_id=client-123&redirect_uri=http://localhost:3000/callback&code_challenge=${CHALLENGE}&code_challenge_method=S256&state=xyz
```

4) Exchange code for tokens:

```bash
curl -X POST http://localhost:8080/token \
	-d grant_type=authorization_code \
	-d client_id=client-123 \
	-d code=RECEIVED_CODE \
	-d code_verifier="${VERIFIER}"
```

Response:

```json
{
	"access_token": "...",
	"id_token": "...",
	"refresh_token": "...",
	"token_type": "Bearer",
	"expires_in": 900
}
```

## Refresh Token Rotation

```bash
curl -X POST http://localhost:8080/token \
	-d grant_type=refresh_token \
	-d client_id=client-123 \
	-d refresh_token=PREVIOUS_REFRESH_TOKEN
```

Returns a new `access_token` and rotated `refresh_token`. The previous refresh token is revoked.

## Logout (CSRF Protected)

- Requires a `csrf_token` cookie and matching `X-CSRF-Token` header.

```bash
curl -X POST http://localhost:8080/logout \
	-H "X-CSRF-Token: $(cat /tmp/csrf)" \
	--cookie "csrf_token=$(cat /tmp/csrf)"
```

Clears `sentinel_access` cookie and records token `jti` in `revoked_tokens`.

## OIDC and JWKS

- Discovery: `curl http://localhost:8080/.well-known/openid-configuration`
- JWKS: `curl http://localhost:8080/jwks.json`

`access_token` and `id_token` use RS256 and include a `kid`. Verify signatures against the JWKS keys.

## Roles and Scopes

- RBAC tables (`roles`, `scopes`, `role_scopes`) determine `scope` claim of access tokens.
- Assign a `role_id` to users and map role→scopes to influence issued token scopes.

## Development Notes

- HTTPS: The session cookie uses `Secure: true`. Serve via HTTPS locally or adjust cookie flags for development only.
- PKCE: Only `S256` is supported.
- Issuer: Currently hardcoded to `http://localhost:8080` in `cmd/server/main.go`.
- Keys: Active signing key must exist in `signing_keys` with `active=true`. Keys are reloaded from DB every minute.

## Troubleshooting

- `DATABASE_URL not set`: export a proper Postgres DSN.
- `no active signing key`: insert at least one active RSA key in `signing_keys`.
- Cannot stay logged in locally: ensure HTTPS or relax cookie `Secure` flag in dev.

## License

This repository is for learning and experimentation. Integrate responsibly and review security considerations before production use.

