package security

import (
	"testing"
)

func TestSecureRandom(t *testing.T) {
	data := SecureRandom(16)
	if len(data) != 16 {
		t.Error("Incorrect length of random data returned")
		t.Fail()
	}
}
