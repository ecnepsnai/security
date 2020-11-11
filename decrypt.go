package security

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"
)

// Decrypt will decrypt the given encrypted data using AES-256-GCM with the given passphrase.
// The passphrase can be a user provided value, and is hashed using scrypt before being used.
//
// Will return error if an empty passphrase or data is provided.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("Passphrase is required")
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("Invalid encrypted data")
	}

	key := PassphraseToEncryptionKey(passphrase)
	if len(key) != 32 {
		return nil, fmt.Errorf("Invalid key length after hashing")
	}

	return DecryptKey(data, key)
}

// DecryptKey will decrypt the given encrypted data using AES-256-GCM with the given 32-byte key.
//
// Will return error if an invaid key or data is provided.
func DecryptKey(data []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Invalid key")
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("Invalid encrypted data")
	}

	r := bufio.NewReader(bytes.NewReader(data))
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}

	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	rawdata, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return rawdata, nil
}
