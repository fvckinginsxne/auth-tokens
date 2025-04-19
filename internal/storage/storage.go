package storage

import "errors"

var (
	ErrUserExists     = errors.New("user already exists")
	ErrTokenNotExists = errors.New("token does not exist")
)
