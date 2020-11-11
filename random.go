package security

import (
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
)

// RandomBytes generate random bytes of specified length. suitable for cryptographical use.
func RandomBytes(length uint16) []byte {
	randB := make([]byte, length)
	rand.Read(randB)
	return randB
}

// RandomNumber generate a random number within the specified range.
// Not suitable for cryptographically use.
func RandomNumber(min int, max int) int {
	return mrand.Intn(max-min) + min
}

// RandomString generate a random string (hex characters) with the length of random entropy.
// Returned string will be exactly 2* longer than `randomLength`. For example, if you want a string that's 32 characters long, specify 16 for the random length.
// Suitable for cryptographical use.
func RandomString(randomLength uint16) string {
	return hex.EncodeToString(RandomBytes(randomLength))
}
