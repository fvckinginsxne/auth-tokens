package model

import "time"

type Token struct {
	UserID      string
	TokenHash   string
	TokenPairID string
	IP          string
	ExpiresAt   time.Time
}
