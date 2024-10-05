package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/valu/encrpytion/internal/model"
	"github.com/valu/encrpytion/internal/repository"
	"github.com/valu/encrpytion/pkg/crypto"
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
	_, err := rand.Read(keyMaterial)
	if err != nil {
		http.Error(w, "Failed to generate key material", http.StatusInternalServerError)
		return
	}

	key.EncryptedKeyMaterial = keyMaterial

	err = h.db.CreateKey(r.Context(), &key)
	if err != nil {
		http.Error(w, "Failed to create key", http.StatusInternalServerError)
		return
	}

	if err := jsn.WriteJSON(w, http.StatusOK, key, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *KeyHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(r.URL.Query().Get("key_id"))
	if err != nil {
		http.Error(w, "Invalid key_id", http.StatusBadRequest)
		return
	}

	key, err := h.db.GetKey(r.Context(), keyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := jsn.WriteJSON(w, http.StatusOK, key, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *KeyHandler) UpdateKeyStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID  string `json:"key_id"`
		Status string `json:"status"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	keyID, err := uuid.Parse(req.KeyID)
	if err != nil {
		http.Error(w, "Invalid key_id", http.StatusBadRequest)
		return
	}

	err = h.db.UpdateKeyStatus(r.Context(), keyID, req.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *KeyHandler) ListActiveKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.db.ListActiveKeys(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := jsn.WriteJSON(w, http.StatusOK, keys, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *KeyHandler) EncryptMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
	}
	if err := jsn.ReadJSON(w, r, &req); err != nil {
		h.log.Error().Err(err).Msg("Failed to read request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	currentKey, err := h.db.GetCurrentActiveKey(r.Context())
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to get current key")
		http.Error(w, "Failed to get current key", http.StatusInternalServerError)
		return
	}

	encryptedMessage, encryptedDataKey, err := crypto.EncryptMessage([]byte(req.Message), currentKey)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to encrypt message")
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	response := struct {
		EncryptedMessage string `json:"encrypted_message"`
		EncryptedDataKey string `json:"encrypted_data_key"`
		KeyVersion       int    `json:"key_version"`
	}{
		EncryptedMessage: base64.StdEncoding.EncodeToString(encryptedMessage),
		EncryptedDataKey: base64.StdEncoding.EncodeToString(encryptedDataKey),
		KeyVersion:       currentKey.Version,
	}

	if err := jsn.WriteJSON(w, http.StatusOK, response, nil); err != nil {
		h.log.Error().Err(err).Msg("Failed to write response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *KeyHandler) DecryptMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EncryptedMessage string `json:"encrypted_message"`
		EncryptedDataKey string `json:"encrypted_data_key"`
	}
	if err := jsn.ReadJSON(w, r, &req); err != nil {
		h.log.Error().Err(err).Msg("Failed to read request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	keyVersions, err := h.db.GetAllKeyVersions(r.Context())
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to get key versions")
		http.Error(w, "Failed to retrieve key versions", http.StatusInternalServerError)
		return
	}

	encryptedMessage, err := base64.StdEncoding.DecodeString(req.EncryptedMessage)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to decode encrypted_message")
		http.Error(w, "Invalid encrypted_message", http.StatusBadRequest)
		return
	}

	encryptedDataKey, err := base64.StdEncoding.DecodeString(req.EncryptedDataKey)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to decode encrypted_data_key")
		http.Error(w, "Invalid encrypted_data_key", http.StatusBadRequest)
		return
	}

	decryptedMessage, err := crypto.DecryptMessage(encryptedMessage, encryptedDataKey, keyVersions)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to decrypt message")
		http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		DecryptedMessage string `json:"decrypted_message"`
	}{
		DecryptedMessage: string(decryptedMessage),
	}

	if err := jsn.WriteJSON(w, http.StatusOK, response, nil); err != nil {
		h.log.Error().Err(err).Msg("Failed to write response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, "Failed to generate new key", http.StatusInternalServerError)
		return
	}

	err = h.db.RotateKey(ctx, currentKey.KeyID, &newKey)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to rotate key")
		http.Error(w, "Failed to rotate key", http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
