package main


import (
	"log"
	"net/http"
	"os"
	"github.com/joho/godotenv"

	"github.com/SAMurai-16/sentinel-idp/internal/auth"
	"github.com/SAMurai-16/sentinel-idp/internal/oauth"
	"github.com/SAMurai-16/sentinel-idp/internal/storage"
	"github.com/SAMurai-16/sentinel-idp/internal/middleware"
	jwtutil "github.com/SAMurai-16/sentinel-idp/internal/jwt"


)


func main(){

	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	
	dsn := os.Getenv("DATABASE_URL")
	if dsn == ""{
		log.Fatal("DATABASE_URL not set")
	}

	db,err := storage.Open(dsn)
	if err!= nil {
		log.Fatal(err)
	}

	defer db.Close()


	privateKey, err := jwtutil.LoadPrivateKey("keys/private.pem")
	if err != nil {
		log.Fatal("failed to load private key:", err)
	}

	publicKey, err := jwtutil.LoadPublicKey("keys/public.pem")
	if err != nil {
	log.Fatal("failed to load public key:", err)
	}

	signer := &jwtutil.Signer{
		DB: db,
		PrivateKey: privateKey,
		KeyID:      "sentinel-key-1",
		Issuer:     "http://localhost:8080",
	}


	jwk := jwtutil.PublicKeyToJWK(publicKey, "sentinel-key-1")

	jwks := jwtutil.JWKS{
	Keys: []jwtutil.JWK{jwk},
	}


	authHandler := &auth.Handler{DB: db}
	oauthHandler := &oauth.AuthorizeHandler{DB: db}

	tokenHandler := &oauth.TokenHandler{
	DB:     db,
	Signer: signer,
	}

	jwksHandler := &jwtutil.JWKSHandler{JWKS: jwks}



	mux := http.NewServeMux()
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/login/", authHandler.Login)

	protected := middleware.RequireSession(db, http.HandlerFunc(home))
	mux.Handle("/", protected)
	mux.Handle("/authorize",
	middleware.RequireSession(db, http.HandlerFunc(oauthHandler.Authorize)),
	)
	mux.Handle("/logout",
	middleware.RequireCSRF(
		http.HandlerFunc(oauthHandler.Logout),
	),
	)



	mux.HandleFunc("/token", tokenHandler.Token)
	mux.Handle("/.well-known/jwks.json", jwksHandler)

	mux.HandleFunc("/revoked", oauthHandler.IsRevoked)



	log.Println("Sentinel listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))

}




func home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Sentinel running"))
}