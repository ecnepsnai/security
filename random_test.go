package security

import (
	"testing"
)

func TestSecureRandom(t *testing.T) {
	data := SecureRandom(16)
	if len(data) != 16 {
		t.Error("Incorrect length of random data returned")
	}
}

func TestRandomNumber(t *testing.T) {
	number := RandomNumber(100, 999)
	if number < 100 || number > 999 {
		t.Errorf("Random number is not within specified range (%d)", number)
	}
}

func TestRandomString(t *testing.T) {
	str := RandomString(12)
	length := len(str)
	if length < 12 {
		t.Errorf("Random string is less than the specified maximum length: %d", length)
	}
}
