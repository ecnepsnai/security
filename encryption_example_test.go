package security_test

import (
	"encoding/hex"
	"fmt"

	"github.com/ecnepsnai/security"
)

func ExampleEncrypt() {
	data := []byte("Hello world!")
	passphrase := "hunter1"
	encryptedBytes, err := security.Encrypt(data, passphrase)
	if err != nil {
		// Encryption failed for some reason
		panic(err)
	}

	// Encrypted bytes are not ASCII, you should convert it to
	// hex if you plan to store it as a string
	fmt.Printf("Encrypted bytes: '%s'\n", hex.EncodeToString(encryptedBytes))
}

func ExampleDecrypt() {
	encryptedBytes, _ := hex.DecodeString("c2a2ae6cb914c62b8c60b2697202649e66b02fac34b686ded43a4148de6537e1f3135ec351eedcf2")
	passphrase := "hunter1"

	decryptedBytes, err := security.Decrypt(encryptedBytes, passphrase)
	if err != nil {
		// Decryption failed, password was incorrect?
		panic(err)
	}

	// Do something with the decrypted bytes
	fmt.Printf("Decrypted bytes: '%s'\n", decryptedBytes)

	// output: Decrypted bytes: 'Hello world!'
}
