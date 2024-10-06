package api

import (
	"crypto/rand"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/valu/encrpytion/internal/model"
	"github.com/valu/encrpytion/internal/repository"
	"github.com/valu/encrpytion/pkg/errs"
	"github.com/valu/encrpytion/pkg/jsn"
)

type KeyHandler struct {
	db  *repository.DB
	log *zerolog.Logger
}

func (h *KeyHandler) CreateKey(w http.ResponseWriter, r *http.Request) {
	key := model.EncryptionKey{
		KeyID:          uuid.New(),
		CreationDate:   time.Now(),
		Status:         string(model.KeyStatusActive),
		Version:        1,
		ExpirationDate: time.Now().AddDate(1, 0, 0), // 1 year from now
	}

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial) // -> be aware of package crpyto/rand and not math/rand
	if err != nil {
		errs.ServerErrorResponse(w, r, err)
		return
	}

	key.EncryptedKeyMaterial = keyMaterial

	err = h.db.CreateKey(r.Context(), &key)
	if err != nil {
		errs.ServerErrorResponse(w, r, err)
		return
	}

	if err := jsn.WriteJSON(w, http.StatusOK, key, nil); err != nil {
		errs.ServerErrorResponse(w, r, err)
		return
	}
}

func (h *KeyHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(r.URL.Query().Get("key_id"))
	if err != nil {
		errs.BadRequestResponse(w, r, err)
		return
	}

	key, err := h.db.GetKey(r.Context(), keyID)
	if err != nil {
		errs.NotFoundResponse(w, r)
		return
	}

	if err := jsn.WriteJSON(w, http.StatusOK, key, nil); err != nil {
		errs.ServerErrorResponse(w, r, err)
		return
	}
}

func (h *KeyHandler) ListActiveKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.db.ListActiveKeys(r.Context())
	if err != nil {
		errs.ServerErrorResponse(w, r, err)
		return
	}

	if err := jsn.WriteJSON(w, http.StatusOK, keys, nil); err != nil {
		errs.BadRequestResponse(w, r, err)
		return
	}
}

func (h *KeyHandler) RotateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	currentKey, err := h.db.GetCurrentActiveKey(ctx)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to get current active key")
		http.Error(w, "Failed to get current active key", http.StatusInternalServerError)
		return
	}

	newKey := model.EncryptionKey{
		KeyID:          uuid.New(),
		CreationDate:   time.Now(),
		Status:         string(model.KeyStatusActive),
		Version:        currentKey.Version + 1,
		ExpirationDate: time.Now().AddDate(1, 0, 0), // 1 year from now
	}

	newKey.EncryptedKeyMaterial = make([]byte, 32)
	if _, err := rand.Read(newKey.EncryptedKeyMaterial); err != nil {
		h.log.Error().Err(err).Msg("Failed to generate new key material")
		errs.ServerErrorResponse(w, r, err)
		return
	}

	err = h.db.RotateKey(ctx, currentKey.KeyID, &newKey)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to rotate key")
		errs.ServerErrorResponse(w, r, err)
		return
	}

	response := struct {
		Message       string `json:"message"`
		NewKeyID      string `json:"new_key_id"`
		NewKeyVersion int    `json:"new_key_version"`
	}{
		Message:       "Key rotated successfully",
		NewKeyID:      newKey.KeyID.String(),
		NewKeyVersion: newKey.Version,
	}

	if err := jsn.WriteJSON(w, http.StatusOK, response, nil); err != nil {
		h.log.Error().Err(err).Msg("Failed to write response")
		errs.ServerErrorResponse(w, r, err)
		return
	}
}
