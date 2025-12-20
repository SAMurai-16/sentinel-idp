package middleware

import (
	"database/sql"
	"net/http"
	"time"
)

func RequireSession(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("sentinel_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		var expires time.Time
		err = db.QueryRow(
			"SELECT expires_at FROM sessions WHERE id = $1",
			cookie.Value,
		).Scan(&expires)

		if err != nil || time.Now().After(expires) {
			http.SetCookie(w, &http.Cookie{
				Name:   "sentinel_session",
				Value:  "",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
