package oauth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"time"
)

type AuthorizeHandler struct {
	DB *sql.DB
}

func randomCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *AuthorizeHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	// 1. Parse params
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	state := r.URL.Query().Get("state")

	if clientID == "" || redirectURI == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// 2. Validate client + redirect URI
	var dbRedirect string
	err := h.DB.QueryRow(
		"SELECT redirect_uri FROM oauth_clients WHERE client_id=$1",
		clientID,
	).Scan(&dbRedirect)

	if err != nil || dbRedirect != redirectURI {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}

	// 3. Validate PKCE
	if err := ValidatePKCE(codeChallenge, codeChallengeMethod); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 4. Get logged-in user (session already enforced by middleware)
	cookie, _ := r.Cookie("sentinel_session")

	var userID int
	err = h.DB.QueryRow(
		"SELECT user_id FROM sessions WHERE id=$1",
		cookie.Value,
	).Scan(&userID)

	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// 5. Issue authorization code
	code := randomCode()
	expires := time.Now().Add(60 * time.Second)

	_, err = h.DB.Exec(
		`INSERT INTO authorization_codes
		 (code, client_id, user_id, code_challenge, expires_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		code, clientID, userID, codeChallenge, expires,
	)

	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// 6. Redirect back to client
	http.Redirect(
		w,
		r,
		redirectURI+"?code="+code+"&state="+state,
		http.StatusFound,
	)
}
