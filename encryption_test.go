package security

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	data := []byte("Hello world!")
	passphrase := "hunter1"
	encryptedBytes, err := Encrypt(data, passphrase)
	if err != nil {
		t.Errorf("Error encrypting bytes: %s", err.Error())
		t.Fail()
	}
	if encryptedBytes == nil || len(encryptedBytes) <= 0 {
		t.Error("Encrypted bytes is empty")
		t.Fail()
	}
}

func TestDecrypt(t *testing.T) {
	encryptedBytes, err := hex.DecodeString("ffbfc29be0532922c24cd71a24e56a0e5a7363247cd9629572d73007010f3d9ae3a069e964c54b728b")
	if err != nil {
		t.Errorf("Invalid encrypted bytes: %s", err.Error())
		t.Fail()
	}
	if len(encryptedBytes) <= 0 {
		t.Error("Encrypted bytes is empty")
		t.Fail()
	}
	passphrase := "hunter1"

	decryptedBytes, err := Decrypt(encryptedBytes, passphrase)
	if err != nil {
		t.Errorf("Error decrypting bytes: %s", err.Error())
		t.Fail()
	}
	if decryptedBytes == nil || len(decryptedBytes) <= 0 {
		t.Error("decrypted bytes is empty")
		t.Fail()
	}
	expected := "Hello world!"
	actual := string(decryptedBytes)
	if actual != expected {
		t.Errorf("Incorrect plain-text value, expected '%s' got '%s'", expected, actual)
		t.Fail()
	}
}

func TestDecryptIncorrectPassphrase(t *testing.T) {
	encryptedBytes, err := hex.DecodeString("ffbfc29be0532922c24cd71a24e56a0e5a7363247cd9629572d73007010f3d9ae3a069e964c54b728b")
	if err != nil {
		t.Errorf("Invalid encrypted bytes: %s", err.Error())
		t.Fail()
	}
	if len(encryptedBytes) <= 0 {
		t.Error("Encrypted bytes is empty")
		t.Fail()
	}
	passphrase := "not correct :("

	decryptedBytes, err := Decrypt(encryptedBytes, passphrase)
	if err == nil {
		t.Errorf("No error seen decrypting bytes with incorrect passphrase")
		t.Fail()
	}
	if decryptedBytes != nil {
		t.Errorf("Decrypted bytes returned with incorrect passphrase")
		t.Fail()
	}
}

// Encrypt data using a string passphrase
func ExampleEncrypt() {
	data := []byte("Hello world!")
	passphrase := "hunter1"
	encryptedBytes, err := Encrypt(data, passphrase)
	if err != nil {
		// Encryption failed for some reason
	}

	// Encrypted bytes is not in ASCII, you should convert it to
	// hex if you plan to store it as a string
	hex.EncodeToString(encryptedBytes)
}

func ExampleDecrypt() {
	encryptedBytes := []byte{}
	passphrase := "hunter1"

	decryptedBytes, err := Decrypt(encryptedBytes, passphrase)
	if err != nil {
		// Decryption failed, password was incorrect?
	}

	// Do something with the decrypted bytes
	fmt.Printf("Decrypted bytes: '%s'", decryptedBytes)
}
