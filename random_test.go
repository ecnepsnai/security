package security_test

import (
	"testing"

	"github.com/ecnepsnai/security"
)

func TestRandomBytes(t *testing.T) {
	t.Parallel()

	data := security.RandomBytes(16)
	if len(data) != 16 {
		t.Error("Incorrect length of random data returned")
	}
}

func TestRandomNumber(t *testing.T) {
	t.Parallel()

	number := security.RandomNumber(100, 999)
	if number < 100 || number > 999 {
		t.Errorf("Random number is not within specified range (%d)", number)
	}
}

func TestRandomString(t *testing.T) {
	t.Parallel()

	str := security.RandomString(12)
	length := len(str)
	if length < 12 {
		t.Errorf("Random string is less than the specified maximum length: %d", length)
	}
}
