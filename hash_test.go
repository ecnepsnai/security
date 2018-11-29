package security

import (
	"testing"
)

var userPassword = "hunter2"

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

func TestHashKey(t *testing.T) {
	key := HashKey(userPassword)
	length := len(key)
	if length != 32 {
		t.Errorf("Incorrect key length. Expected 32 got %d", length)
		t.Fail()
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
