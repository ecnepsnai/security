package security_test

import (
	"encoding/hex"
	"testing"

	"github.com/ecnepsnai/security"
)

func TestEncrypt(t *testing.T) {
	t.Parallel()

	data := []byte("Hello world!")
	passphrase := "hunter1"
	encryptedBytes, err := security.Encrypt(data, passphrase)
	if err != nil {
		t.Fatalf("Error encrypting bytes: %s", err.Error())
	}
	if encryptedBytes == nil || len(encryptedBytes) <= 0 {
		t.Fatalf("Encrypted bytes is empty")
	}
}

func TestDecrypt(t *testing.T) {
	t.Parallel()

	encryptedBytes, err := hex.DecodeString("44d63abe175b07c5673690b45a2d12eaf2318965a16ac1a3245a15073b25f68fa91719ab0ecfd961")
	if err != nil {
		t.Fatalf("Invalid encrypted bytes: %s", err.Error())
	}
	if len(encryptedBytes) <= 0 {
		t.Fatalf("Encrypted bytes is empty")
	}
	passphrase := "hunter1"

	decryptedBytes, err := security.Decrypt(encryptedBytes, passphrase)
	if err != nil {
		t.Fatalf("Error decrypting bytes: %s", err.Error())
	}
	if decryptedBytes == nil || len(decryptedBytes) <= 0 {
		t.Fatalf("decrypted bytes is empty")
	}
	expected := "Hello world!"
	actual := string(decryptedBytes)
	if actual != expected {
		t.Fatalf("Incorrect plain-text value, expected '%s' got '%s'", expected, actual)
	}
}

func TestDecryptIncorrectPassphrase(t *testing.T) {
	t.Parallel()

	encryptedBytes, err := hex.DecodeString("ffbfc29be0532922c24cd71a24e56a0e5a7363247cd9629572d73007010f3d9ae3a069e964c54b728b")
	if err != nil {
		t.Fatalf("Invalid encrypted bytes: %s", err.Error())
	}
	if len(encryptedBytes) <= 0 {
		t.Fatalf("Encrypted bytes is empty")
	}
	passphrase := "not correct :("

	decryptedBytes, err := security.Decrypt(encryptedBytes, passphrase)
	if err == nil {
		t.Fatalf("No error seen decrypting bytes with incorrect passphrase")
	}
	if decryptedBytes != nil {
		t.Fatalf("Decrypted bytes returned with incorrect passphrase")
	}
}

func TestEncryptBadParameters(t *testing.T) {
	var data []byte
	var err error

	// No data
	data, err = security.Encrypt([]byte{}, "hunter2")
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt nothing")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// No passphrase
	data, err = security.Encrypt([]byte("foo"), "")
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt without passphrase")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Invalid key
	data, err = security.EncryptKey([]byte("foo"), []byte("bar"))
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt with invalid key")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Incorrect data length
	data, err = security.EncryptKey([]byte{}, security.PassphraseToEncryptionKey("hunter2"))
	if err == nil {
		t.Fatalf("No error seen when trying to encrypt incorrect data")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}
}

func TestDecryptBadParameters(t *testing.T) {
	var data []byte
	var err error

	// No data
	data, err = security.Decrypt([]byte{}, "hunter2")
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt nothing")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// No passphrase
	data, err = security.Decrypt([]byte("foo"), "")
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt without passphrase")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Invalid key
	data, err = security.DecryptKey([]byte("foo"), []byte("bar"))
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt with invalid key")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}

	// Incorrect data length
	data, err = security.DecryptKey([]byte("foo"), security.PassphraseToEncryptionKey("hunter2"))
	if err == nil {
		t.Fatalf("No error seen when trying to decrypt incorrect data")
	}
	if data != nil {
		t.Fatalf("Unexpected data")
	}
}
