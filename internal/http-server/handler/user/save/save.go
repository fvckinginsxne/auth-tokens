package save

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
	authSevice "auth-tokens/internal/service/auth"
)

type Request struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type Auth interface {
	Register(ctx context.Context, email, password string) error
}

func New(
	ctx context.Context,
	log *slog.Logger,
	auth Auth,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handler.user.New"

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

		if err := auth.Register(ctx, req.Email, req.Password); err != nil {
			log.Error("failed to register user", sl.Err(err))

			if errors.Is(err, authSevice.ErrUserExists) {
				w.WriteHeader(http.StatusConflict)

				render.JSON(w, r, resp.Error("user with this email already exists"))
				return
			}

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, resp.Error("internal error"))
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}
