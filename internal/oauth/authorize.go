package oauth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthorizeHandler struct {
	DB *sql.DB
}

type authorizeRequest struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
}

type ConsentPageData struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Username            string
}

func randomCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func authorizeRequestFromValues(values url.Values) authorizeRequest {
	return authorizeRequest{
		ClientID:            values.Get("client_id"),
		RedirectURI:         values.Get("redirect_uri"),
		CodeChallenge:       values.Get("code_challenge"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
		State:               values.Get("state"),
	}
}

func redirectWithOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("error", errorCode)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *AuthorizeHandler) validateAuthorizeRequest(req authorizeRequest) error {
	if req.ClientID == "" || req.RedirectURI == "" {
		return sql.ErrNoRows
	}

	var dbRedirect string
	err := h.DB.QueryRow(
		"SELECT redirect_uri FROM oauth_clients WHERE client_id=$1",
		req.ClientID,
	).Scan(&dbRedirect)
	if err != nil || dbRedirect != req.RedirectURI {
		return sql.ErrNoRows
	}

	return ValidatePKCE(req.CodeChallenge, req.CodeChallengeMethod)
}

func (h *AuthorizeHandler) sessionUser(r *http.Request) (int, string, error) {
	cookie, err := r.Cookie("sentinel_session")
	if err != nil {
		return 0, "", err
	}

	var (
		userID   int
		username string
	)
	err = h.DB.QueryRow(
		`SELECT users.id, users.username
		 FROM sessions
		 JOIN users ON users.id = sessions.user_id
		 WHERE sessions.id=$1`,
		cookie.Value,
	).Scan(&userID, &username)
	return userID, username, err
}

func (h *AuthorizeHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req authorizeRequest
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		req = authorizeRequestFromValues(r.PostForm)
	} else {
		req = authorizeRequestFromValues(r.URL.Query())
	}

	if err := h.validateAuthorizeRequest(req); err != nil {
		http.Error(w, "invalid authorize request", http.StatusBadRequest)
		return
	}

	userID, username, err := h.sessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("web/templates/consent.html")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, ConsentPageData{
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			State:               req.State,
			Username:            username,
		})
		return
	}

	if r.FormValue("decision") != "allow" {
		redirectWithOAuthError(w, r, req.RedirectURI, req.State, "access_denied")
		return
	}

	code := randomCode()
	expires := time.Now().Add(60 * time.Second)

	_, err = h.DB.Exec(
		`INSERT INTO authorization_codes
		 (code, client_id, user_id, code_challenge, expires_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		code, req.ClientID, userID, req.CodeChallenge, expires,
	)

	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	redirectWithCode(w, r, req.RedirectURI, code, req.State)
}

func (h *AuthorizeHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie("sentinel_access")
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	tokenStr := cookie.Value

	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err == nil {
		claims := token.Claims.(jwt.MapClaims)

		if jtiVal, ok := claims["jti"]; ok {
			if jti, ok := jtiVal.(string); ok {
				h.DB.Exec(
					"INSERT INTO revoked_tokens (jti) VALUES ($1) ON CONFLICT DO NOTHING",
					jti,
				)
			}
		}
	}

	print("token revoked")

	// Delete cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_access",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthorizeHandler) IsRevoked(w http.ResponseWriter, r *http.Request) {
	jti := r.URL.Query().Get("jti")
	if jti == "" {
		http.Error(w, "missing jti", http.StatusBadRequest)
		return
	}

	var exists bool
	err := h.DB.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM revoked_tokens WHERE jti = $1)",
		jti,
	).Scan(&exists)

	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	if exists {
		w.WriteHeader(http.StatusOK) // revoked
		return
	}

	w.WriteHeader(http.StatusNotFound) // not revoked
}
