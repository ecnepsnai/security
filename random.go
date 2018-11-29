package security

import (
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
)

// SecureRandom generate random bytes of specified length.
// Sutible for cryptographical use.
func SecureRandom(length uint16) []byte {
	randB := make([]byte, length)
	rand.Read(randB)
	return randB
}

// RandomNumber generate a random number within the specified range.
// Not sutible for cryptogrpahical use.
func RandomNumber(min int, max int) int {
	return mrand.Intn(max-min) + min
}

// RandomString generate a random string (hex characters) with the length of random entropy. Returned string will be around 2* longer than `length`.
// Sutible for cryptographical use.
func RandomString(length uint16) string {
	return hex.EncodeToString(SecureRandom(length))
}
