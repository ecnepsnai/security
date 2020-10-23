package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Encrypt will encrypt the given data using AES-256-GCM with the given passphrase. The passphrase can be a
// user provided value (meaning it does not need to be 32 bytes).
func Encrypt(data []byte, passphrase string) ([]byte, error) {
	key := PassphraseToEncryptionKey(passphrase)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	var writer bytes.Buffer
	writer.Write(nonce)
	writer.Write(ciphertext)

	return writer.Bytes(), nil
}
