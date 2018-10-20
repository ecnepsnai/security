# Security

Security provides simple bindings for security related tasks
in golang. This includes encrypting & decrypting data, hashing user passwords,
and hashing non-password type data.

# Encryption

Security provides a simple interface to encrypt data using AES-256. Passphrases are hashed with scrypt.

## Encrypting Data

```golang
data := []byte("Hello world!")
passphrase := "hunter1"
encryptedBytes, err := Encrypt(data, passphrase)
if err != nil {
    // Encryption failed for some reason
}

// Encrypted bytes is not in ASCII, you should convert it to
// hex if you plan to store it as a string
hex.EncodeToString(encryptedBytes)
```

## Decrypting Data

```golang
encryptedBytes := []byte{}
passphrase := "hunter1"

decryptedBytes, err := Decrypt(encryptedBytes, passphrase)
if err != nil {
    // Decryption failed, password was incorrect?
}

// Do something with the decrypted bytes
fmt.Printf("Decrypted bytes: '%s'", decryptedBytes)
```

# Password Hashing

Security provides an interface for hashing password using BCrypt.

## Hash Password

```golang
plainTextPassword := "hunter2"
password := HashPassword(plainTextPassword)

// BCryptHash is just a string type with some methods attached to it
fmt.Printf("Hash: %s\n", password.String())
```

## Check Password

```golang
passwordHash := BCryptHash("...")
plainTextPassword := "hunter2"

if passwordHash.Compare(plainTextPassword) {
    // Password was correct
} else {
    // Password was incorrect
}
```
