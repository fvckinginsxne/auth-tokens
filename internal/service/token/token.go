package token

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
	"auth-tokens/internal/storage"
)

const (
	accessTokenExp  = 30 * time.Minute
	refreshTokenExp = 24 * time.Hour
	refreshTokenLen = 48
	uuidLen         = 16
)

var (
	ErrUserNotExists       = errors.New("user not found")
	ErrTokenNotExists      = errors.New("token does not exist")
	ErrInvalidAccessToken  = errors.New("invalid token")
	ErrInvalidRefreshToken = errors.New("invalid token")
	ErrIPWasModified       = errors.New("ip was modified")
	ErrAccessTokenExpired  = errors.New("token expired")
	ErrRefreshTokenExpired = errors.New("token expired")
)

type SaverRefresher interface {
	SaveToken(ctx context.Context, token *model.Token) error
	RefreshToken(ctx context.Context, token *model.Token) error
}

type TokenProvider interface {
	TokenByUserID(ctx context.Context, guid string) (*model.Token, error)
}

type UserProvider interface {
	UserExists(ctx context.Context, guid string) (bool, error)
}

type Token struct {
	log                 *slog.Logger
	jwtSecret           []byte
	tokenSaverRefresher SaverRefresher
	userProvider        UserProvider
	tokenProvider       TokenProvider
}

func New(
	log *slog.Logger,
	jwtSecret string,
	saverRefresher SaverRefresher,
	userProvider UserProvider,
	tokenProvider TokenProvider,
) *Token {
	return &Token{
		log:                 log,
		jwtSecret:           []byte(jwtSecret),
		tokenSaverRefresher: saverRefresher,
		userProvider:        userProvider,
		tokenProvider:       tokenProvider,
	}
}

func (t *Token) Generate(
	ctx context.Context,
	guid, ip string,
) (accessToken string, refreshToken string, err error) {
	const op = "service.token.Generate"

	log := t.log.With(slog.String("op", op))

	tokenPairID := generateUUID()

	accessToken, err = t.generateAccessToken(guid, ip, tokenPairID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Debug("access token", slog.String("token", accessToken))

	refreshToken = generateRefreshToken()

	log.Debug("refresh token", slog.String("token", refreshToken))

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	userExists, err := t.userProvider.UserExists(ctx, guid)
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

	log.Debug("saving token", slog.Any("token", token))

	if err = t.tokenSaverRefresher.SaveToken(ctx, token); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("token saved successfully")

	return accessToken, refreshToken, nil
}

func (t *Token) Refresh(
	ctx context.Context,
	accessToken, refreshToken, ip string,
) (updatedAccessToken, updatedRefreshToken string, err error) {
	const op = "service.token.Refresh"

	log := t.log.With(slog.String("op", op))

	tokenPayload, err := t.parseJWT(accessToken)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Debug("parsed access token", slog.Any("token", tokenPayload))

	token, err := t.tokenProvider.TokenByUserID(ctx, tokenPayload.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotExists) {
			return "", "", fmt.Errorf("%s: %w", op, ErrTokenNotExists)
		}

		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := validateRefreshToken(refreshToken, token, tokenPayload); err != nil {
		if errors.Is(err, ErrIPWasModified) {
			//TODO: send warning message to email

			return "", "", fmt.Errorf("%s: %w", op, ErrIPWasModified)
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	tokenPairID := generateUUID()

	accessToken, err = t.generateAccessToken(tokenPayload.UserID, ip, tokenPairID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshToken = generateRefreshToken()

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	token = &model.Token{
		UserID:      tokenPayload.UserID,
		TokenHash:   string(refreshTokenHash),
		TokenPairID: tokenPairID,
		ExpiresAt:   time.Now().Add(refreshTokenExp),
	}

	if err := t.tokenSaverRefresher.RefreshToken(ctx, token); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

func (t *Token) parseJWT(token string) (*model.Token, error) {
	accessParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return t.jwtSecret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrAccessTokenExpired
		}
		return nil, ErrInvalidAccessToken
	}

	claims, ok := accessParsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, err
	}

	return &model.Token{
		UserID:      claims["user_id"].(string),
		IP:          claims["ip"].(string),
		TokenPairID: claims["token_pair_id"].(string),
		ExpiresAt:   time.Unix(int64(claims["exp"].(float64)), 0),
	}, nil
}

func (t *Token) generateAccessToken(guid, ip, tokenPairID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":       guid,
		"ip":            ip,
		"token_pair_id": tokenPairID,
		"exp":           time.Now().Add(accessTokenExp).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(t.jwtSecret)
}

func validateRefreshToken(refreshToken string, token, tokenPayload *model.Token) error {
	if err := verifyRefreshToken(refreshToken, token.TokenHash); err != nil {
		return err
	}

	if token.TokenPairID != tokenPayload.TokenPairID {
		return ErrInvalidRefreshToken
	}

	if token.IP != tokenPayload.IP {
		return ErrIPWasModified
	}

	if time.Now().After(token.ExpiresAt) {
		return ErrRefreshTokenExpired
	}

	return nil
}

func verifyRefreshToken(refreshToken, hash string) error {
	decodedRefresh, err := base64.URLEncoding.DecodeString(refreshToken)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), decodedRefresh)
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidRefreshToken
		}

		return err
	}

	return nil
}

func generateRefreshToken() string {
	b := make([]byte, refreshTokenLen)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateUUID() string {
	b := make([]byte, uuidLen)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
