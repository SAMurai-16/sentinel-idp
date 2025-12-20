package auth

import (
	"time"

	"github.com/google/uuid"
)

func NewSessionID() string {
	return uuid.NewString()
}

func SessionExpiry() time.Time {
	return time.Now().Add(24 * time.Hour)
}
