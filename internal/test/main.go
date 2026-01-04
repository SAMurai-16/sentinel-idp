package main

import (
	"log"
	"os"

	"github.com/SAMurai-16/sentinel-idp/internal/jwt"
	"github.com/SAMurai-16/sentinel-idp/internal/storage"
	"github.com/joho/godotenv"
)

func main() {


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

	_, err = jwtutil.LoadKeys(db)
	if err != nil {
		log.Fatal(err)
	}


}
