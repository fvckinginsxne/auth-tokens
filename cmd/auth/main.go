package main

import (
	"log/slog"
	"os"

	"auth/internal/config"
)

func main() {
	cfg := config.MustLoad()

	log := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)

	log.Debug("Config fetched: ", slog.Any("config", cfg))
}
