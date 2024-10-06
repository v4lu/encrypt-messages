package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/valu/encrpytion/internal/repository"
)

func SetupRoutes(database *repository.DB, log *zerolog.Logger) http.Handler {
	kh := &KeyHandler{db: database, log: log}
	ch := &CryptoHandler{db: database, log: log}
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/v1/keys", func(r chi.Router) {
		r.Post("/", kh.CreateKey)
		r.Get("/", kh.GetKey)
		r.Get("/active", kh.ListActiveKeys)
		r.Post("/rotate", kh.RotateKey)
	})

	r.Route("/v1/crypto", func(r chi.Router) {
		r.Post("/encrypt", ch.EncryptMessage)
		r.Post("/decrypt", ch.DecryptMessage)
	})

	return r
}
