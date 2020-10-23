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
		t.Fatalf("Password validation suceeded with incorrect password")
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
		t.Fatalf("Password validation suceeded with incorrect password")
	}
	if bytes.Equal([]byte(*hash), userPassword) {
		t.Fatalf("Hashed password was equal to raw password")
	}
}
