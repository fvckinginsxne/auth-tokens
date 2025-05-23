package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"auth-tokens/internal/config"
)

func main() {
	var (
		migrationsPath string
		action         string
		forceVersion   int
	)

	flag.StringVar(&migrationsPath, "migrations-path", "", "Path to the migrations folder")
	flag.StringVar(&action, "action", "", "Action to perform: up (apply migrations) or down (rollback migrations)")
	flag.IntVar(&forceVersion, "force-version", 0, "Force version to rollback")

	flag.Parse()

	cfg := config.MustLoad()

	if migrationsPath == "" {
		panic("migrations path is required")
	}

	postgresURL := dbURL(cfg)

	m, err := migrate.New("file://"+migrationsPath, postgresURL)
	if err != nil {
		panic(err)
	}
	defer func() { _, _ = m.Close() }()

	if forceVersion > 0 {
		if err := m.Force(forceVersion); err != nil {
			panic(err)
		}

		fmt.Printf("Forced database to version %d\n", forceVersion)
	}

	switch action {
	case "up":
		if err := applyMigrations(m); err != nil {
			panic(err)
		}
	case "down":
		if err := rollbackMigrations(m); err != nil {
			panic(err)
		}
	}
}

func applyMigrations(m *migrate.Migrate) error {
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("Nothing to migrate")

			return nil
		}

		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	fmt.Println("Migrations applied successfully")

	return nil
}

func rollbackMigrations(m *migrate.Migrate) error {
	if err := m.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("Nothing to rollback")

			return nil
		}

		return fmt.Errorf("failed to rollback migrations: %w", err)
	}

	fmt.Println("Migrations rolled back successfully")

	return nil
}

func dbURL(cfg *config.Config) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.DB.User,
		cfg.DB.Password,
		cfg.DB.Host,
		cfg.DB.Port,
		cfg.DB.Name,
	)
}
