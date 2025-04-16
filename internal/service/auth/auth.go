package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/bcrypt"

	"auth-tokens/internal/domain/model"
	"auth-tokens/internal/lib/logger/sl"
	"auth-tokens/internal/storage"
)

var (
	ErrUserExists = errors.New("user already exists")
)

type UserSaver interface {
	SaveUser(ctx context.Context, user *model.User) error
}

type Auth struct {
	log       *slog.Logger
	userSaver UserSaver
}

func New(log *slog.Logger, userSaver UserSaver) *Auth {
	return &Auth{
		log:       log,
		userSaver: userSaver,
	}
}

func (a *Auth) Register(ctx context.Context, email, password string) error {
	const op = "service.auth.Register"

	log := a.log.With(slog.String("op", op))

	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	user := &model.User{
		Email:    email,
		PassHash: passHash,
	}

	if err := a.userSaver.SaveUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("user already exists", sl.Err(err))

			return fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered successfully")

	return nil
}
