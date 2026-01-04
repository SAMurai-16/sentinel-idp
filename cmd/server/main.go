package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/SAMurai-16/sentinel-idp/internal/auth"
	jwtutil "github.com/SAMurai-16/sentinel-idp/internal/jwt"
	"github.com/SAMurai-16/sentinel-idp/internal/middleware"
	"github.com/SAMurai-16/sentinel-idp/internal/oauth"
	"github.com/SAMurai-16/sentinel-idp/internal/oidc"
	"github.com/SAMurai-16/sentinel-idp/internal/storage"
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









	// privateKey, err := jwtutil.LoadPrivateKey("keys/private.pem")
	// if err != nil {
	// 	log.Fatal("failed to load private key:", err)
	// }

	// publicKey, err := jwtutil.LoadPublicKey("keys/public.pem")
	// if err != nil {
	// log.Fatal("failed to load public key:", err)
	// }


	keyManager, err := jwtutil.LoadKeys(db)
	if err != nil {
		log.Fatal(err)
	}
	
	

	signer := &jwtutil.Signer{
	DB:         db,
	Issuer:     "http://localhost:8080",
	KeyManager: keyManager,
	}


	authHandler := &auth.Handler{DB: db}
	oauthHandler := &oauth.AuthorizeHandler{DB: db}

	tokenHandler := &oauth.TokenHandler{
	DB:     db,
	Signer: signer,
	}

	jwksHandler := &jwtutil.JWKSHandler{KeyManager: keyManager}

	issuer := "http://localhost:8080"

	go func() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := keyManager.ReloadFromDB(db); err != nil {
			log.Println("key reload failed:", err)
		} else {
			log.Println("signing keys reloaded")
		}
	}
	}()



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
	mux.Handle("/jwks.json", jwksHandler)

	mux.HandleFunc("/revoked", oauthHandler.IsRevoked)

	mux.Handle(
	"/.well-known/openid-configuration",
	oidc.DiscoveryHandler(issuer),
	)



	log.Println("Sentinel listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))

}




func home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Sentinel running"))
}