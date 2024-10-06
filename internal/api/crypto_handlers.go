package api

import (
	"encoding/base64"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/valu/encrpytion/internal/repository"
	"github.com/valu/encrpytion/pkg/crypto"
	"github.com/valu/encrpytion/pkg/errs"
	"github.com/valu/encrpytion/pkg/jsn"
)

type CryptoHandler struct {
	db  *repository.DB
	log *zerolog.Logger
}

func (h *CryptoHandler) EncryptMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
	}
	if err := jsn.ReadJSON(w, r, &req); err != nil {
		h.log.Error().Err(err).Msg("Failed to read request")
		errs.BadRequestResponse(w, r, err)
		return
	}

	currentKey, err := h.db.GetCurrentActiveKey(r.Context())
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to get current key")
		errs.ServerErrorResponse(w, r, err)
		return
	}

	encryptedMessage, encryptedDataKey, err := crypto.EncryptMessage([]byte(req.Message), currentKey)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to encrypt message")
		errs.ServerErrorResponse(w, r, err)
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

func (h *CryptoHandler) DecryptMessage(w http.ResponseWriter, r *http.Request) {
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
