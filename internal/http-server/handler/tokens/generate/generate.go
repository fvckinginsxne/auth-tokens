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
	tokenGen "auth-tokens/internal/service/token-gen"
)

type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenGenerator interface {
	Generate(ctx context.Context, uuid, ip string) (accessToken string, refreshToken string, err error)
}

func New(
	ctx context.Context,
	log *slog.Logger,
	tokenGenerator TokenGenerator,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.tokens.generate.New"

		log := log.With(slog.String("op", op))

		guid := chi.URLParam(r, "guid")
		if guid == "" {
			log.Error("guid is required")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, resp.Error("guid is required"))
			return
		}

		ip := r.RemoteAddr

		log.Info("generating tokens:",
			slog.String("guid", guid),
			slog.String("ip", ip),
		)

		log.Info("generating new tokens")

		accessToken, refreshToken, err := tokenGenerator.Generate(ctx, guid, ip)
		if err != nil {
			if errors.Is(err, tokenGen.ErrUserNotExists) {
				log.Error("user not exists")

				w.WriteHeader(http.StatusBadRequest)

				render.JSON(w, r, resp.Error("user not exists"))
				return
			}
			log.Error("failed to generate tokens:", sl.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, resp.Error("internal error"))
			return
		}

		log.Info("tokens generated successfully")

		w.WriteHeader(http.StatusCreated)

		render.JSON(w, r, Response{
			accessToken,
			refreshToken,
		})
	}
}
