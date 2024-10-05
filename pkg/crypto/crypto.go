package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/valu/encrpytion/internal/model"
)

func EncryptMessage(message []byte, masterKey *model.EncryptionKey) ([]byte, []byte, error) {
	// Generate a new data key
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, nil, err
	}

	// Encrypt the message with the data key
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	encryptedMessage := gcm.Seal(nonce, nonce, message, nil)

	// Encrypt the data key with the master key
	masterBlock, err := aes.NewCipher(masterKey.EncryptedKeyMaterial)
	if err != nil {
		return nil, nil, err
	}

	masterGCM, err := cipher.NewGCM(masterBlock)
	if err != nil {
		return nil, nil, err
	}

	masterNonce := make([]byte, masterGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, masterNonce); err != nil {
		return nil, nil, err
	}

	encryptedDataKey := masterGCM.Seal(masterNonce, masterNonce, dataKey, nil)

	return encryptedMessage, encryptedDataKey, nil
}

func DecryptMessage(encryptedMessage, encryptedDataKey []byte, masterKey *model.EncryptionKey) ([]byte, error) {
	// Decrypt the data key
	masterBlock, err := aes.NewCipher(masterKey.EncryptedKeyMaterial)
	if err != nil {
		return nil, err
	}

	masterGCM, err := cipher.NewGCM(masterBlock)
	if err != nil {
		return nil, err
	}

	masterNonceSize := masterGCM.NonceSize()
	if len(encryptedDataKey) < masterNonceSize {
		return nil, errors.New("encrypted data key is too short")
	}

	masterNonce, encryptedDataKeyContent := encryptedDataKey[:masterNonceSize], encryptedDataKey[masterNonceSize:]
	dataKey, err := masterGCM.Open(nil, masterNonce, encryptedDataKeyContent, nil)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedMessage) < nonceSize {
		return nil, errors.New("encrypted message is too short")
	}

	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
