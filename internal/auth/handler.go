package auth

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// Handler holds DB connection
type Handler struct {
	DB *sql.DB
}

// JSON request/response types
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Message  string `json:"message"`
}

type RegisterClientRequest struct {
	RedirectURI string `json:"redirect_uri"`
}

type RegisterClientResponse struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Message     string `json:"message"`
}

// Template data types
type RegisterClientPageData struct {
	Success     bool
	Error       string
	ClientID    string
	RedirectURI string
}

type RegisterPageData struct {
	Success  bool
	Error    string
	Username string
	UserID   int
	Message  string
}

type LoginPageData struct {
	Next  string
	Error string
}

func safeNextPath(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// Login handles GET/POST login (existing behavior)
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("web/templates/login.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		tmpl.Execute(w, LoginPageData{Next: safeNextPath(r.URL.Query().Get("next"))})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	next := safeNextPath(r.FormValue("next"))

	var userID int
	var hash string

	err = h.DB.QueryRow(
		"SELECT id, password_hash FROM users WHERE username=$1",
		username,
	).Scan(&userID, &hash)

	if err != nil || !CheckPassword(hash, password) {
		w.WriteHeader(http.StatusUnauthorized)
		tmpl.Execute(w, LoginPageData{Next: next, Error: "Invalid username or password"})
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

	http.Redirect(w, r, next, http.StatusFound)
}

// Register serves GET form or accepts POST (form or JSON)
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFiles("web/templates/register.html")
		tmpl.Execute(w, RegisterPageData{})
		return
	}

	// POST: decide JSON vs form
	ct := r.Header.Get("Content-Type")
	if ct == "application/json" || ct == "application/json; charset=utf-8" {
		h.registerJSON(w, r)
	} else {
		h.registerForm(w, r)
	}
}

func (h *Handler) registerForm(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	tmpl, _ := template.ParseFiles("web/templates/register.html")

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		tmpl.Execute(w, RegisterPageData{Error: "Username and password are required"})
		return
	}

	// Check existing user
	var existingID int
	err := h.DB.QueryRow("SELECT id FROM users WHERE username=$1", username).Scan(&existingID)
	if err == nil {
		w.WriteHeader(http.StatusConflict)
		tmpl.Execute(w, RegisterPageData{Error: "User already exists"})
		return
	}

	// Hash
	hash, err := HashPassword(password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tmpl.Execute(w, RegisterPageData{Error: "Failed to process password"})
		return
	}

	// Insert
	var userID int
	err = h.DB.QueryRow(
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
		username, hash,
	).Scan(&userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tmpl.Execute(w, RegisterPageData{Error: "Failed to create user"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	tmpl.Execute(w, RegisterPageData{Success: true, Username: username, UserID: userID, Message: "User registered successfully! You can now login."})
}

func (h *Handler) registerJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "username and password required"})
		return
	}

	// Hash
	hash, err := HashPassword(req.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to hash password"})
		return
	}

	// Check existing
	var existingID int
	err = h.DB.QueryRow("SELECT id FROM users WHERE username=$1", req.Username).Scan(&existingID)
	if err == nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "user already exists"})
		return
	}

	// Insert
	var userID int
	err = h.DB.QueryRow(
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
		req.Username, hash,
	).Scan(&userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to create user"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{UserID: userID, Username: req.Username, Message: "user registered successfully"})
}

// RegisterClient serves GET form or accepts POST (form or JSON)
func (h *Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, _ := template.ParseFiles("web/templates/register-client.html")
		tmpl.Execute(w, RegisterClientPageData{})
		return
	}

	ct := r.Header.Get("Content-Type")
	if ct == "application/json" || ct == "application/json; charset=utf-8" {
		h.registerClientJSON(w, r)
	} else {
		h.registerClientForm(w, r)
	}
}

func (h *Handler) registerClientForm(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.FormValue("redirect_uri")
	tmpl, _ := template.ParseFiles("web/templates/register-client.html")

	if redirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		tmpl.Execute(w, RegisterClientPageData{Error: "Redirect URI is required"})
		return
	}

	clientID := uuid.NewString()
	_, err := h.DB.Exec("INSERT INTO oauth_clients (client_id, redirect_uri) VALUES ($1, $2)", clientID, redirectURI)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tmpl.Execute(w, RegisterClientPageData{Error: "Failed to create OAuth client"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	tmpl.Execute(w, RegisterClientPageData{Success: true, ClientID: clientID, RedirectURI: redirectURI})
}

func (h *Handler) registerClientJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.RedirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "redirect_uri required"})
		return
	}

	clientID := uuid.NewString()
	_, err := h.DB.Exec("INSERT INTO oauth_clients (client_id, redirect_uri) VALUES ($1, $2)", clientID, req.RedirectURI)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to create OAuth client"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterClientResponse{ClientID: clientID, RedirectURI: req.RedirectURI, Message: "OAuth client registered successfully"})
}
