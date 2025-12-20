package main

import (
	"fmt"
	"github.com/SAMurai-16/sentinel-idp/internal/auth"
)

func main() {
	hash, _ := auth.HashPassword("password123")
	fmt.Println(hash)
}
