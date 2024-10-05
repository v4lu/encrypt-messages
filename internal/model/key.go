package model

import (
	"time"

	"github.com/google/uuid"
)

type EncryptionKey struct {
	ID                   int64     `json:"id"`
	KeyID                uuid.UUID `json:"key_id"`
	EncryptedKeyMaterial []byte    `json:"encrypted_key_material"`
	CreationDate         time.Time `json:"creation_date"`
	ExpirationDate       time.Time `json:"expiration_date"`
	Status               string    `json:"status"`
	Version              int       `json:"version"`
}

type KeyStatus string

const (
	KeyStatusActive   KeyStatus = "ACTIVE"
	KeyStatusInactive KeyStatus = "INACTIVE"
	KeyStatusRotated  KeyStatus = "ROTATED"
)
