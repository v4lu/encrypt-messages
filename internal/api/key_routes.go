package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/valu/encrpytion/internal/repository"
)

func SetupRoutes(database *repository.DB, log *zerolog.Logger) http.Handler {
	handler := &KeyHandler{db: database, log: log}

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/v1/keys", func(r chi.Router) {
		r.Post("/", handler.CreateKey)
		r.Get("/", handler.GetKey)
		r.Patch("/status", handler.UpdateKeyStatus)
		r.Get("/active", handler.ListActiveKeys)
	})

	r.Route("/v1/crypto", func(r chi.Router) {
		r.Post("/encrypt", handler.EncryptMessage)
		r.Post("/decrypt", handler.DecryptMessage)
	})

	return r
}
