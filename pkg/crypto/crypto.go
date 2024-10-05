package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

	// Include key version in the encrypted message
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, uint32(masterKey.Version))

	// Prepend the version to the message
	messageWithVersion := append(versionBytes, message...)

	// Encrypt the message with version
	encryptedMessage := gcm.Seal(nil, nonce, messageWithVersion, nil)

	// Prepend the nonce to the encrypted message
	encryptedMessageWithNonce := append(nonce, encryptedMessage...)

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

	return encryptedMessageWithNonce, encryptedDataKey, nil
}

func DecryptMessage(encryptedMessage, encryptedDataKey []byte, keyVersions map[uint32]*model.EncryptionKey) ([]byte, error) {
	// Create a dummy cipher for NonceSize
	dummyBlock, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		return nil, fmt.Errorf("failed to create dummy cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(dummyBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedMessage) < nonceSize {
		return nil, errors.New("encrypted message is too short")
	}
	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]

	// Try decrypting with each available key
	var decryptedMessage []byte
	var decryptionErr error
	for _, masterKey := range keyVersions {
		// Decrypt the data key
		masterBlock, err := aes.NewCipher(masterKey.EncryptedKeyMaterial)
		if err != nil {
			continue // Try next key
		}
		masterGCM, err := cipher.NewGCM(masterBlock)
		if err != nil {
			continue // Try next key
		}
		masterNonceSize := masterGCM.NonceSize()
		if len(encryptedDataKey) < masterNonceSize {
			continue // Try next key
		}
		masterNonce, encryptedDataKeyContent := encryptedDataKey[:masterNonceSize], encryptedDataKey[masterNonceSize:]
		dataKey, err := masterGCM.Open(nil, masterNonce, encryptedDataKeyContent, nil)
		if err != nil {
			continue // Try next key
		}

		// Decrypt the message
		block, err := aes.NewCipher(dataKey)
		if err != nil {
			continue // Try next key
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue // Try next key
		}

		decryptedWithVersion, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			decryptionErr = err
			continue // Try next key
		}

		// Successfully decrypted
		decryptedMessage = decryptedWithVersion
		decryptionErr = nil
		break
	}

	if decryptedMessage == nil {
		return nil, fmt.Errorf("failed to decrypt with any key: %v", decryptionErr)
	}

	// Extract and verify the version
	if len(decryptedMessage) < 4 {
		return nil, errors.New("decrypted message is too short")
	}
	binary.BigEndian.Uint32(decryptedMessage[:4])

	// Remove the version number from the decrypted message
	return decryptedMessage[4:], nil
}
