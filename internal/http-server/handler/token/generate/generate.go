package generate

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	resp "auth-tokens/internal/lib/api/response"
	"auth-tokens/internal/lib/logger/sl"
	tokenService "auth-tokens/internal/service/token"
)

type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenGenerator interface {
	Generate(ctx context.Context, uuid, ip string) (accessToken, refreshToken string, err error)
}

func New(
	ctx context.Context,
	log *slog.Logger,
	tokenGenerator TokenGenerator,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.token.generate.New"

		log := log.With(slog.String("op", op))

		guid := chi.URLParam(r, "guid")
		if guid == "" {
			log.Error("guid is required")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, resp.Error("guid is required"))
			return
		}

		ip := r.RemoteAddr

		log.Info("generating token:",
			slog.String("guid", guid),
			slog.String("ip", ip),
		)

		log.Info("generating new token")

		accessToken, refreshToken, err := tokenGenerator.Generate(ctx, guid, ip)
		if err != nil {
			switch {
			case errors.Is(err, tokenService.ErrUserNotExists):
				log.Error("user does not exist")

				sendResponseError(w, r, "user does not exist", http.StatusBadRequest)
				return
			default:
				log.Error("failed to generate token:", sl.Err(err))

				sendResponseError(w, r, "internal error", http.StatusInternalServerError)
				return
			}
		}

		log.Info("token generated successfully")

		w.WriteHeader(http.StatusCreated)

		render.JSON(w, r, Response{
			accessToken,
			refreshToken,
		})
	}
}

func sendResponseError(w http.ResponseWriter, r *http.Request, errMsg string, code int) {
	w.WriteHeader(code)

	render.JSON(w, r, resp.Error(errMsg))
}
