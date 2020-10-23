package security

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// HashedPassword describes a hashed password
type HashedPassword []byte

// HashingAlgorithm describes an enum type for a hashing algorithm
type HashingAlgorithm string

const (
	// HashingAlgorithmBCrypt constant value representing the BCrypt hashing algorithm
	HashingAlgorithmBCrypt = HashingAlgorithm("1")
	// HashingAlgorithmArgon2id constant value representing the Argon2id hashing algorithm
	HashingAlgorithmArgon2id = HashingAlgorithm("2")
)

// HashPassword returns a hashed representation of the provided password that is sutible for storage. Current algoritm
// used is Argon2ID.
func HashPassword(password []byte) (*HashedPassword, error) {
	return HashPasswordAlgorithm(password, HashingAlgorithmArgon2id)
}

// HashPasswordAlgorithm returns a hashed representation of the provided password that is sutible for storage using the
// given hashing algorithm.
func HashPasswordAlgorithm(password []byte, alg HashingAlgorithm) (*HashedPassword, error) {
	var hash []byte
	var err error
	switch alg {
	case HashingAlgorithmBCrypt:
		hash, err = hashPasswordBCrypt(password)
		if err != nil {
			return nil, err
		}
	case HashingAlgorithmArgon2id:
		salt := hex.EncodeToString(RandomBytes(6))
		hash = hashPasswordArgon2id(password, []byte(salt))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown algorithm %s", alg)
	}
	p := HashedPassword(fmt.Sprintf("%s$%s", alg, hash))
	return &p, nil
}

func hashPasswordBCrypt(password []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func hashPasswordArgon2id(password []byte, salt []byte) []byte {
	hash := argon2.IDKey(password, salt, 1, 64*1024, getThreads(), 32)
	return []byte(fmt.Sprintf("%s$%x", salt, hash))
}

func getThreads() uint8 {
	threads := uint8(4)
	ncpu := runtime.NumCPU()
	if ncpu > 0 && ncpu < 255 {
		threads = uint8(ncpu)
	}
	return threads
}

func compareArgon2id(hash, password []byte) bool {
	hashSalt := hash[2:14]
	hashHexData := hash[15:]

	hashData := make([]byte, hex.DecodedLen(len(hashHexData)))
	hex.Decode(hashData, hashHexData)

	result := argon2.IDKey(password, hashSalt, 1, 64*1024, getThreads(), 32)
	return bytes.Equal(result, hashData)
}

func compareBCrypt(hash, password []byte) bool {
	return bcrypt.CompareHashAndPassword(hash[2:], password) == nil
}

// Algorithm get the algorithm used for this hashed password.
func (p HashedPassword) Algorithm() HashingAlgorithm {
	alg := p[0]
	switch HashingAlgorithm(alg) {
	case HashingAlgorithmBCrypt:
		return HashingAlgorithmBCrypt
	case HashingAlgorithmArgon2id:
		return HashingAlgorithmArgon2id
	}

	return HashingAlgorithm("-1")
}

// Compare does password match the hashed password. Returns true if matched.
func (p HashedPassword) Compare(password []byte) bool {
	switch p.Algorithm() {
	case HashingAlgorithmBCrypt:
		return compareBCrypt([]byte(p), password)
	case HashingAlgorithmArgon2id:
		return compareArgon2id([]byte(p), password)
	default:
		fmt.Printf("Unknown hashing algorithm")
		return false
	}
}

// Upgrade generate a new password object if the current hashing algorithm could be replaced with a better option.
// Returns nil if no upgraded needed.
func (p HashedPassword) Upgrade(password []byte) *HashedPassword {
	switch p.Algorithm() {
	case HashingAlgorithmBCrypt:
		newPassword, err := HashPasswordAlgorithm(password, HashingAlgorithmArgon2id)
		if err != nil {
			return nil
		}
		return newPassword
	}

	return nil
}
