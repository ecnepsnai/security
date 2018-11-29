package security

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// HashedPassword represents a hash string
type HashedPassword string

// HashPassword generates a hash for the given string
func HashPassword(raw string) HashedPassword {
	hash, _ := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	return HashedPassword(hash)
}

// HashKey hash a string sutible for a AES-256 key (32 bytes)
func HashKey(raw string) []byte {
	key, _ := scrypt.Key([]byte(raw), nil, 32768, 8, 1, 32)
	return key
}

// HashString generates a SHA265 hexedecimal hash for the given string
func HashString(raw string) string {
	hasher := sha256.New()
	hasher.Write([]byte(raw))
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha
}

// Compare compares a raw string with a provided hash
func (hash HashedPassword) Compare(raw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) == nil
}

// String returns the hash string representation
func (hash HashedPassword) String() string {
	return string(hash)
}
