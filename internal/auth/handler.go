package auth

import (
	"database/sql"
	"net/http"
)

type Handler struct {
	DB *sql.DB
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "web/templates/login.html")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var userID int
	var hash string

	err := h.DB.QueryRow(
		"SELECT id, password_hash FROM users WHERE username=$1",
		username,
	).Scan(&userID, &hash)

	if err != nil || !CheckPassword(hash, password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	sessionID := NewSessionID()
	expires := SessionExpiry()

	_, err = h.DB.Exec(
		"INSERT INTO sessions (id, user_id, expires_at) VALUES ($1,$2,$3)",
		sessionID, userID, expires,
	)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_session",
		Value:    sessionID,
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}
