package security_test

import (
	"bytes"
	"testing"

	"github.com/ecnepsnai/security"
)

var userPassword = []byte("hunter2")

func TestHashPassword(t *testing.T) {
	t.Parallel()

	hash, err := security.HashPassword(userPassword)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	if !hash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if hash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}

func TestHashPasswordBCrypt(t *testing.T) {
	t.Parallel()

	hash, err := security.HashPasswordAlgorithm(userPassword, security.HashingAlgorithmBCrypt)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	if !hash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if hash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}

func TestUpgradePassword(t *testing.T) {
	t.Parallel()

	oldHash, err := security.HashPasswordAlgorithm(userPassword, security.HashingAlgorithmBCrypt)
	if err != nil {
		t.Fatalf("Unable to hash password: %s", err.Error())
	}

	newHash := oldHash.Upgrade(userPassword)
	if newHash == nil {
		t.Fatalf("Error upgrading password")
	}

	if !newHash.Compare(userPassword) {
		t.Fatalf("Password verification failed with correct password")
	}
	if newHash.Compare([]byte("incorrect")) {
		t.Fatalf("Password validation succeeded with incorrect password")
	}
}

func TestUnknownHashingAlgorithm(t *testing.T) {
	t.Parallel()

	hash, err := security.HashPasswordAlgorithm(userPassword, security.HashingAlgorithm("MD5"))
	if err == nil {
		t.Fatalf("No error seen when trying to hash password with unknown algorithm")
	}

	if hash != nil {
		t.Fatalf("Hash returned for invlaid algorithm")
	}
}

func TestCompareUnknownType(t *testing.T) {
	t.Parallel()

	// This is supposed to panic
	defer func() {
		recover()
	}()

	whatEvenIsThis := security.HashedPassword([]byte("DOGS_ARE_VERY_GOOD"))
	whatEvenIsThis.Algorithm()
	t.Fatalf("No panic seen when one expected")
}
