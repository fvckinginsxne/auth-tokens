package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"auth-tokens/internal/config"
	"auth-tokens/internal/http-server/handler/token/generate"
	"auth-tokens/internal/http-server/handler/token/refresh"
	"auth-tokens/internal/http-server/handler/user/save"
	"auth-tokens/internal/lib/logger/sl"
	authService "auth-tokens/internal/service/auth"
	tokenService "auth-tokens/internal/service/token"
	"auth-tokens/internal/storage/postgres"
)

const (
	shutdownTimeout = 30 * time.Second
)

func main() {
	cfg := config.MustLoad()

	log := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	postgresURL := dbURL(cfg)

	log.Debug("postgres connection URL:", slog.String("url", postgresURL))

	storage, err := postgres.New(postgresURL)
	if err != nil {
		panic(err)
	}

	token := tokenService.New(log, cfg.JWTSecret, storage, storage, storage)

	auth := authService.New(log, storage)

	router := chi.NewRouter()

	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	router.Route("/auth", func(r chi.Router) {
		r.Route("/token", func(r chi.Router) {
			r.Post("/{guid}", generate.New(ctx, log, token))
			r.Post("/refresh", refresh.New(ctx, log, token))
		})
		r.Post("/", save.New(ctx, log, auth))
	})

	srv := &http.Server{
		Addr:         serverAddr(cfg),
		Handler:      router,
		ReadTimeout:  cfg.Server.Timeout,
		WriteTimeout: cfg.Server.Timeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("starting server", slog.String("address", srv.Addr))

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("failed to start server", sl.Err(err))
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-serverErr:
		log.Error("server error", sl.Err(err))
		cancel()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("failed to shutdown server", sl.Err(err))
	}

	if err := storage.Close(shutdownCtx); err != nil {
		log.Error("failed to close storage", sl.Err(err))
	}

	log.Warn("server stopped")
}

func dbURL(cfg *config.Config) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.DB.User,
		cfg.DB.Password,
		cfg.DB.Host,
		cfg.DB.DockerPort,
		cfg.DB.Name,
	)
}

func serverAddr(cfg *config.Config) string {
	return cfg.Server.Host + ":" + cfg.Server.Port
}
