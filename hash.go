package security

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/scrypt"
)

// Hasher describes an object that can hash data
type Hasher struct {
	hasher hash.Hash
}

// HashSHA256 return the SHA-256 hash of the provided data. Do not use for passwords.
func HashSHA256(raw []byte) []byte {
	return hashWith(raw, sha256.New())
}

// HashSHA256String return a hexedacimal string representing the SHA-256 hash of the provided string. Do not use for passwords.
func HashSHA256String(raw string) string {
	return hashWithString(raw, sha256.New())
}

// HashSHA512 return the SHA-512 hash of the provided data. Do not use for passwords.
func HashSHA512(raw []byte) []byte {
	return hashWith(raw, sha512.New())
}

// HashSHA512String return a hexedacimal string representing the SHA-512 hash of the provided string. Do not use for passwords.
func HashSHA512String(raw string) string {
	return hashWithString(raw, sha512.New())
}

func hashWith(raw []byte, hasher hash.Hash) []byte {
	hasher.Write(raw)
	return hasher.Sum(nil)
}

func hashWithString(raw string, hasher hash.Hash) string {
	return hex.EncodeToString(hashWith([]byte(raw), hasher))
}

// PassphraseToEncryptionKey hash a string sutible for a AES-256 key (32 bytes) using scrypt
func PassphraseToEncryptionKey(raw string) []byte {
	key, _ := scrypt.Key([]byte(raw), nil, 32768, 8, 1, 32)
	return key
}
