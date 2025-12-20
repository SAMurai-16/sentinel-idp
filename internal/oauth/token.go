package oauth

import (
	"context"
	"database/sql"
	"net/http"

	jwtutil "github.com/SAMurai-16/sentinel-idp/internal/jwt"
)

type TokenHandler struct {
	DB     *sql.DB
	Signer *jwtutil.Signer
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

	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "unsupported grant type", http.StatusBadRequest)
		return
	}

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

	// 🔥 SINGLE-USE CODE CONSUMPTION
	authCode, err := ConsumeAuthCode(ctx, tx, code)
	if err != nil {
		tx.Rollback()
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	// 🔐 Client binding check
	if authCode.ClientID != clientID {
		tx.Rollback()
		http.Error(w, "client mismatch", http.StatusBadRequest)
		return
	}

	// 🔐 PKCE verification
	if err := VerifyPKCE(verifier, authCode.CodeChallenge); err != nil {
		tx.Rollback()
		http.Error(w, "pkce verification failed", http.StatusBadRequest)
		return
	}

	// 🟢 Issue JWT
	token, err := h.Signer.MintAccessToken(authCode.UserID, clientID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "token signing failed", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{
	  "access_token":"` + token + `",
	  "token_type":"Bearer",
	  "expires_in":900
	}`))
}
