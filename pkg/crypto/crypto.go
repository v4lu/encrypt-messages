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
	// This creates a new 32-byte (256-bit) data key using a cryptographically secure random number generator. again be aware of package it should be crypto/rand not math/rand
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, nil, err
	}

	// This sets up AES encryption using the data key.
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, nil, err
	}

	// GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both confidentiality and integrity.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// A nonce (number used once) is a random number used once to ensure unique encryptions.
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// adds version of master key to message
	// version is 4 bytes long and is the first 4 bytes of the message
	// version is used to determine which master key to use for decryption
	// version is also added to the encrypted message to allow for versioning of the encryption algorithm
	gcm.NonceSize()
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, uint32(masterKey.Version))
	messageWithVersion := append(versionBytes, message...)

	// This encrypts the message (with version) using GCM and prepends the nonce.
	encryptedMessage := gcm.Seal(nil, nonce, messageWithVersion, nil)
	encryptedMessageWithNonce := append(nonce, encryptedMessage...)

	// This sets up AES-GCM encryption using the master key.
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

	// This encrypts the data key using the master key.
	encryptedDataKey := masterGCM.Seal(masterNonce, masterNonce, dataKey, nil)

	return encryptedMessageWithNonce, encryptedDataKey, nil
}

func DecryptMessage(encryptedMessage, encryptedDataKey []byte, keyVersions map[uint32]*model.EncryptionKey) ([]byte, error) {

	// This creates a dummy cipher just to get the nonce size. It's not used for actual decryption.
	dummyBlock, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		return nil, fmt.Errorf("failed to create dummy cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(dummyBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// This separates the nonce from the actual encrypted message.
	nonceSize := gcm.NonceSize()
	if len(encryptedMessage) < nonceSize {
		return nil, errors.New("encrypted message is too short")
	}
	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]

	// This loop tries to decrypt the message using each of the provided master keys
	// For each master key:
	// a. Create a cipher and GCM instance using the master key.
	// b. Extract the master nonce from the encrypted data key.
	// c. Attempt to decrypt the data key using the master key.
	// d. If successful, use the decrypted data key to create a new cipher and GCM instance.
	// e. Attempt to decrypt the message using this data key.
	// f. If successful, break the loop.
	var decryptedMessage []byte
	var decryptionErr error
	for _, masterKey := range keyVersions {
		masterBlock, err := aes.NewCipher(masterKey.EncryptedKeyMaterial)
		if err != nil {
			continue
		}
		masterGCM, err := cipher.NewGCM(masterBlock)
		if err != nil {
			continue
		}
		masterNonceSize := masterGCM.NonceSize()
		if len(encryptedDataKey) < masterNonceSize {
			continue
		}
		masterNonce, encryptedDataKeyContent := encryptedDataKey[:masterNonceSize], encryptedDataKey[masterNonceSize:]
		dataKey, err := masterGCM.Open(nil, masterNonce, encryptedDataKeyContent, nil)
		if err != nil {
			continue
		}

		block, err := aes.NewCipher(dataKey)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}

		decryptedWithVersion, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			decryptionErr = err
			continue
		}

		decryptedMessage = decryptedWithVersion
		decryptionErr = nil
		break
	}

	if decryptedMessage == nil {
		return nil, fmt.Errorf("failed to decrypt with any key: %v", decryptionErr)
	}

	if len(decryptedMessage) < 4 {
		return nil, errors.New("decrypted message is too short")
	}

	// This removes the 4-byte version information that was prepended to the message during encryption.
	binary.BigEndian.Uint32(decryptedMessage[:4])
	return decryptedMessage[4:], nil
}
