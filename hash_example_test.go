package security_test

import (
	"fmt"

	"github.com/ecnepsnai/security"
)

func ExampleHashSHA256() {
	hash := security.HashSHA256([]byte("hunter2"))
	fmt.Printf("%x\n", hash)

	// output: f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7
}

func ExampleHashSHA256String() {
	hash := security.HashSHA256String("hunter2")
	fmt.Printf("%s\n", hash)

	// output: f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7
}

func ExampleHashSHA512() {
	hash := security.HashSHA512([]byte("hunter2"))
	fmt.Printf("%x\n", hash)

	// output: 6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22
}

func ExampleHashSHA512String() {
	hash := security.HashSHA512String("hunter2")
	fmt.Printf("%s\n", hash)

	// output: 6b97ed68d14eb3f1aa959ce5d49c7dc612e1eb1dafd73b1e705847483fd6a6c809f2ceb4e8df6ff9984c6298ff0285cace6614bf8daa9f0070101b6c89899e22
}
