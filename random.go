package security

import "crypto/rand"

// SecureRandom generate random bytes of specified length
func SecureRandom(length uint16) []byte {
	randB := make([]byte, length)
	rand.Read(randB)
	return randB
}
