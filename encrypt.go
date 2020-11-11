package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Encrypt will encrypt the given data using AES-256-GCM with the given passphrase.
// The passphrase can be a user provided value, and is hashed using scrypt before being used.
//
// Will return error if an empty passphrase or data is provided.
func Encrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Cannot encrypt nothing - data length 0")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("Passphrase is required")
	}

	key := PassphraseToEncryptionKey(passphrase)
	if len(key) != 32 {
		return nil, fmt.Errorf("Invalid key length after hashing")
	}

	return EncryptKey(data, key)
}

// EncryptKey will encrypt the given data using AES-256-GCM with the given 32-byte key.
//
// Will return error if an invaid key or data is provided.
func EncryptKey(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Cannot encrypt nothing - data length 0")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("Invalid key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := RandomBytes(12) // 12 is the standard nonce size for GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	var writer bytes.Buffer
	if _, err := writer.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := writer.Write(ciphertext); err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}
