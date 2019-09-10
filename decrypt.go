package security

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
)

// Decrypt decrypt the given data with the provided passphrase
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	key := HashKey(passphrase)

	r := bufio.NewReader(bytes.NewReader(data))
	nonce := make([]byte, 12)
	n, err := r.Read(nonce)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, fmt.Errorf("Invalid data")
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
