package security

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/scrypt"
)

// Decrypt decrypt the given data with the provided passphrase
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), nil, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	r := bufio.NewReader(bytes.NewReader(data))
	nonce, err := r.ReadBytes('$')
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		return nil, fmt.Errorf("Invalid data")
	}

	// Remove delimiter
	nonce = nonce[:len(nonce)-1]

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
