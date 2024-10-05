package main

import (
	"database/sql"
	"fmt"

	"net/http"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valu/encrpytion/internal/api"
	"github.com/valu/encrpytion/internal/repository"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading .env file")
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Logger = log.With().Caller().Logger()

	dbUrl := os.Getenv("DB_URL")
	if dbUrl == "" {
		log.Fatal().Msg("DB_URL environment variable is not set")
	}

	dbInstance, err := initDatabase(dbUrl)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer dbInstance.Close()
	log.Info().Msg("Connected to the DB")

	db := repository.New(dbInstance)

	router := api.SetupRoutes(db, &log.Logger)

	log.Info().Msg("Starting server on :9002")
	if err := http.ListenAndServe(":9002", router); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}

func initDatabase(dbUrl string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dbUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return db, nil
}
