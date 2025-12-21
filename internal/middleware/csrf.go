package middleware

import (
	"log"
	"net/http"
)



func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		

		if r.Method == http.MethodGet ||
			r.Method == http.MethodHead ||
			r.Method == http.MethodOptions {
			log.Println("The method does not require CSRF")
			next.ServeHTTP(w, r)
			return
		}

		csrfCookie, err := r.Cookie("csrf_token")
		if err != nil {
			http.Error(w, "missing csrf cookie", http.StatusForbidden)
			return
		}

		csrfHeader := r.Header.Get("X-CSRF-Token")
		if csrfHeader == "" || csrfHeader != csrfCookie.Value {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}

		

		

		next.ServeHTTP(w, r)
	})
}
