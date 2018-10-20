package security

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// BCryptHash represents a BCrypt hash string
type BCryptHash string

// HashPassword generates a BCrypt hash for the given string
func HashPassword(raw string) BCryptHash {
	hash, _ := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	return BCryptHash(hash)
}

// HashString generates a SHA265 hexedecimal hash for the given string
func HashString(raw string) string {
	hasher := sha256.New()
	hasher.Write([]byte(raw))
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha
}

// Compare compares a raw string with a provided BCrypt hash
func (hash BCryptHash) Compare(raw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) == nil
}

// String returns the hash string representation
func (hash BCryptHash) String() string {
	return string(hash)
}
