package security

import (
	"fmt"
	"testing"
)

var userPassword = "hunter1"

func TestHashPassword(t *testing.T) {
	password := HashPassword(userPassword)
	if !password.Compare(userPassword) {
		t.Error("Password validation failed with correct password")
		t.Fail()
	}
	if password.Compare("incorrect") {
		t.Error("Password validation succeeded with incorrect password")
		t.Fail()
	}
	if password.String() == userPassword {
		t.Error("String value of password was plain-text user password")
		t.Fail()
	}
}

// Hash a password
func ExampleHashPassword() {
	plainTextPassword := "hunter2"
	password := HashPassword(plainTextPassword)

	// BCryptHash is just a string type with some methods attached to it
	fmt.Printf("Hash: %s\n", password.String())
}

// Compare a plain-text password with the BCrypt hash
func ExampleBCryptHash_Compare() {
	passwordHash := BCryptHash("...")
	plainTextPassword := "hunter2"

	if passwordHash.Compare(plainTextPassword) {
		// Password was correct
	} else {
		// Password was incorrect
	}
}

func TestHashString(t *testing.T) {
	hash1 := HashString("go is fun!")
	hash2 := HashString("go is fun!")
	hash3 := HashString("linux is neat!")

	if hash1 != hash2 {
		t.Error("Hash of the same string did not match")
		t.Fail()
	}
	if hash1 == hash3 || hash2 == hash3 {
		t.Error("Hash of different strings matched")
		t.Fail()
	}
}
