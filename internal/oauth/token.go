package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	jwtutil "github.com/SAMurai-16/sentinel-idp/internal/jwt"
	"github.com/google/uuid"
)

type TokenHandler struct {
	DB     *sql.DB
	Signer *jwtutil.Signer
}


	func generateRefreshToken() (raw string, hash string) {
	b := make([]byte, 64)
	rand.Read(b)

	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}




func(h *TokenHandler) handleAuthorizationCode(w http.ResponseWriter,r *http.Request){
		code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	verifier := r.FormValue("code_verifier")

	if code == "" || clientID == "" || verifier == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	//Single-use auth code
	authCode, err := ConsumeAuthCode(ctx, tx, code)
	if err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}


	if authCode.ClientID != clientID {
		http.Error(w, "client mismatch", http.StatusBadRequest)
		return
	}

	
	if err := VerifyPKCE(verifier, authCode.CodeChallenge); err != nil {
		http.Error(w, "pkce verification failed", http.StatusBadRequest)
		return
	}

	//mint access token
	accessToken, err := h.Signer.MintAccessToken(authCode.UserID, clientID)
	if err != nil {
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}

	idToken, err := h.Signer.MintIDToken(
	authCode.UserID,
	clientID,
	authCode.ExpiresAt,
	)
	if err != nil {
	http.Error(w, "id token signing failed", http.StatusInternalServerError)
	return
	}

	// print(idToken)


	//Create refresh token
	rawRT, hashRT := generateRefreshToken()
	rtID := uuid.New()

	_, err = tx.Exec(`
		INSERT INTO refresh_tokens
		(id, user_id, client_id, token_hash, expires_at)
		VALUES ($1,$2,$3,$4, now() + interval '30 days')
	`,
		rtID,
		authCode.UserID,
		clientID,
		hashRT,
	)
	if err != nil {
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}


	if err := tx.Commit(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"id_token": idToken,
		"refresh_token": rawRT,
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}




func (h *TokenHandler) revokeRefreshFamily(tx *sql.Tx, id uuid.UUID) {
	tx.Exec(`
		UPDATE refresh_tokens
		SET revoked=true
		WHERE id=$1 OR parent_id=$1
	`, id)
}


func hashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}



func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {

	rawRT := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if rawRT == "" || clientID == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}

	hashRT := hashRefreshToken(rawRT)

	ctx := context.Background()
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var (
		rtID      uuid.UUID
		userID    int
		revoked   bool
		parentID  *uuid.UUID
		expiresAt time.Time
	)

	err = tx.QueryRow(`
		SELECT id, user_id, revoked, parent_id, expires_at
		FROM refresh_tokens
		WHERE token_hash=$1 AND client_id=$2
	`, hashRT, clientID).Scan(
		&rtID,
		&userID,
		&revoked,
		&parentID,
		&expiresAt,
	)


	if err != nil || revoked || time.Now().After(expiresAt) {
		h.revokeRefreshFamily(tx, rtID)
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}


	_, err = tx.Exec(
		`UPDATE refresh_tokens SET revoked=true WHERE id=$1`,
		rtID,
	)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}


	newRaw, newHash := generateRefreshToken()
	newID := uuid.New()

	_, err = tx.Exec(`
		INSERT INTO refresh_tokens
		(id, user_id, client_id, token_hash, expires_at, parent_id)
		VALUES ($1,$2,$3,$4, now() + interval '30 days', $5)
	`,
		newID, userID, clientID, newHash, rtID,
	)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	accessToken, err := h.Signer.MintAccessToken(userID, clientID)
	if err != nil {
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}


	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": newRaw,
		"token_type":    "Bearer",
		"expires_in":    900,
	})
}





func (h *TokenHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")



	switch grantType {

	case "authorization_code":
	    h.handleAuthorizationCode(w,r)
		return

	case "refresh_token":
		h.handleRefreshToken(w, r)
		return

	default:
		http.Error(w, "unsupported grant type", http.StatusBadRequest)
		return
	}



}
