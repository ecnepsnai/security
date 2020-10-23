package security_test

import (
	"testing"

	"github.com/ecnepsnai/security"
)

func TestHashSHA256(t *testing.T) {
	t.Parallel()

	expected := "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
	result := security.HashSHA256String("hunter2")

	if expected != result {
		t.Errorf("Invalid SHA-256 hash")
	}
}

func TestHashSHA512(t *testing.T) {
	t.Parallel()

	expected := "6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22"
	result := security.HashSHA512String("hunter2")

	if expected != result {
		t.Errorf("Invalid SHA-512 hash")
	}
}
