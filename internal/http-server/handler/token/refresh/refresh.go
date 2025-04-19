package refresh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/render"
	"github.com/go-playground/validator"

	resp "auth-tokens/internal/lib/api/response"
	"auth-tokens/internal/lib/logger/sl"
	tokenService "auth-tokens/internal/service/token"
)

type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Request struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type TokenRefresher interface {
	Refresh(
		ctx context.Context,
		accessToken, refreshToken, ip string,
	) (updatedAccessToken, updatedRefreshToken string, err error)
}

func New(
	ctx context.Context,
	log *slog.Logger,
	tokenRefresher TokenRefresher,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.token.refresh.New"

		log := log.With(slog.String("op", op))

		var req Request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			if errors.Is(err, io.EOF) {
				log.Error("request body is empty")

				w.WriteHeader(http.StatusBadRequest)

				render.JSON(w, r, resp.Error("request body is empty"))
				return
			}

			log.Error("failed to decode request body", sl.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, resp.Error("internal error"))
			return
		}

		log.Info("request body decoded", slog.Any("req", req))

		if err := validator.New().Struct(req); err != nil {
			log.Error("invalid request", sl.Err(err))

			var validateErr validator.ValidationErrors
			if errors.As(err, &validateErr) {

				w.WriteHeader(http.StatusBadRequest)

				render.JSON(w, r, err.Error())
				return
			}
		}

		log.Info("refreshing access token")

		accessToken := r.Header.Get("Authorization")
		if accessToken == "" {
			log.Error("access token is empty")

			w.WriteHeader(http.StatusUnauthorized)

			render.JSON(w, r, resp.Error("access token is required"))
			return
		}

		log.Debug("old access token is", slog.String("old access token", accessToken))

		ip := r.RemoteAddr

		accessToken, refreshToken, err := tokenRefresher.Refresh(
			ctx, accessToken, req.RefreshToken, ip)
		if err != nil {
			switch {
			case errors.Is(err, tokenService.ErrTokenNotExists):
				log.Error("token does not exist")

				sendResponseError(w, r, "token does not exist", http.StatusBadRequest)
				return
			case errors.Is(err, tokenService.ErrInvalidAccessToken):
				log.Error("invalid access token")

				sendResponseError(w, r, "invalid access token", http.StatusUnauthorized)
				return
			case errors.Is(err, tokenService.ErrInvalidRefreshToken):
				log.Error("invalid refresh token")

				sendResponseError(w, r, "invalid refresh token", http.StatusUnauthorized)
				return
			case errors.Is(err, tokenService.ErrAccessTokenExpired):
				log.Error("access token is expired")

				sendResponseError(w, r, "access token is expired", http.StatusUnauthorized)
				return
			case errors.Is(err, tokenService.ErrRefreshTokenExpired):
				log.Error("refresh token is expired")

				sendResponseError(w, r, "refresh token is expired", http.StatusUnauthorized)
				return
			case errors.Is(err, tokenService.ErrIPWasModified):
				log.Error("ip was modified")

				sendResponseError(w, r, "ip was modified", http.StatusUnauthorized)
				return
			default:
				log.Error("failed to refresh token", sl.Err(err))

				sendResponseError(w, r, "internal error", http.StatusInternalServerError)
				return
			}
		}

		log.Info("access token refreshed successfully")

		w.WriteHeader(http.StatusCreated)

		render.JSON(w, r, &Response{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	}
}

func sendResponseError(w http.ResponseWriter, r *http.Request, errMsg string, code int) {
	w.WriteHeader(code)

	render.JSON(w, r, resp.Error(errMsg))
}
