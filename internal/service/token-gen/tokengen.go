package token_gen

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"auth-tokens/internal/domain/model"
)

const (
	accessTokenExp  = 30 * time.Minute
	refreshTokenExp = 24 * time.Hour
	refreshTokenLen = 48
	uuidLen         = 16
)

var (
	ErrUserNotExists = errors.New("user not found")
)

type TokenSaver interface {
	SaveToken(ctx context.Context, token *model.Token) error
}

type UserProvider interface {
	UserExists(ctx context.Context, guid string) (bool, error)
}

type TokenGenerator struct {
	log          *slog.Logger
	jwtSecret    []byte
	tokenSaver   TokenSaver
	userProvider UserProvider
}

func New(
	log *slog.Logger,
	jwtSecret string,
	tokenSaver TokenSaver,
	userProvider UserProvider,
) *TokenGenerator {
	return &TokenGenerator{
		log:          log,
		jwtSecret:    []byte(jwtSecret),
		tokenSaver:   tokenSaver,
		userProvider: userProvider,
	}
}

func (tg *TokenGenerator) Generate(
	ctx context.Context,
	guid, ip string,
) (accessToken string, refreshToken string, err error) {
	const op = "service.tokens-gen.Generate"

	log := tg.log.With(slog.String("op", op))

	tokenPairID := generateUUID()

	accessToken, err = tg.generateAccessToken(guid, ip, tokenPairID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Debug("access token", slog.String("token", accessToken))

	refreshToken = tg.generateRefreshToken()

	log.Debug("refresh token", slog.String("token", refreshToken))

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	userExists, err := tg.userProvider.UserExists(ctx, guid)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if !userExists {
		return "", "", fmt.Errorf("%s: %w", op, ErrUserNotExists)
	}

	token := &model.Token{
		UserID:      guid,
		TokenHash:   string(refreshTokenHash),
		TokenPairID: tokenPairID,
		IP:          ip,
		ExpiresAt:   time.Now().Add(refreshTokenExp),
	}

	log.Debug("saving tokens", slog.Any("tokens", token))

	if err = tg.tokenSaver.SaveToken(ctx, token); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("tokens saved successfully")

	return accessToken, refreshToken, nil
}

func (tg *TokenGenerator) generateAccessToken(guid, ip, tokenPairID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":           guid,
		"ip":            ip,
		"token_pair_id": tokenPairID,
		"exp":           time.Now().Add(accessTokenExp).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(tg.jwtSecret)
}

func (tg *TokenGenerator) generateRefreshToken() string {
	b := make([]byte, refreshTokenLen)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateUUID() string {
	b := make([]byte, uuidLen)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
