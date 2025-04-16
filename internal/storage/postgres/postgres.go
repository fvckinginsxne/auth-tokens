package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"auth-tokens/internal/domain/model"
	"auth-tokens/internal/storage"
)

const (
	uniqueViolationCode = "23505"
)

type Storage struct {
	db *sql.DB
}

func New(connURL string) (*Storage, error) {
	const op = "storage.postgres.New"

	db, err := sql.Open("postgres", connURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveToken(ctx context.Context, token *model.Token) error {
	const op = "storage.postgres.SaveToken"

	stmt, err := s.db.PrepareContext(ctx, `
		INSERT INTO tokens (user_id, token_hash, token_pair_id, ip_address, expires_at) 
		VALUES ($1, $2, $3, $4, $5)
	`)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(
		ctx, token.UserID,
		token.TokenHash,
		token.TokenPairID,
		token.IP,
		token.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) UserExists(ctx context.Context, guid string) (bool, error) {
	const op = "storage.postgres.UserExists"

	var exists bool
	err := s.db.QueryRowContext(ctx, `
        SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)
    `, guid).Scan(&exists)

	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return exists, nil
}

func (s *Storage) SaveUser(ctx context.Context, user *model.User) error {
	const op = "storage.postgres.SaveUser"

	stmt, err := s.db.PrepareContext(ctx, `
		INSERT INTO users (email, pass_hash) VALUES ($1, $2)
	`)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	if _, err = stmt.ExecContext(ctx, user.Email, user.PassHash); err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode {
			return fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) Close(ctx context.Context) error {
	done := make(chan struct{})

	var closeErr error
	go func() {
		closeErr = s.db.Close()
		close(done)
	}()

	select {
	case <-done:
		return closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
