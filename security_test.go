package security_test

import (
	"os"
	"testing"
	"time"

	"github.com/ecnepsnai/security"
)

func TestMain(m *testing.M) {
	security.FailDelay = 1 * time.Millisecond
	os.Exit(m.Run())
}
