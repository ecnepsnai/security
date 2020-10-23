package security_test

import (
	"fmt"

	"github.com/ecnepsnai/security"
)

func ExampleHashPassword() {
	password := []byte("hunter2")
	hashedPassword, err := security.HashPassword(password)
	if err != nil {
		panic(err)
	}

	// hashedPassword contains the algorithm used, the salt (if applicable), and the hash data
	// it is safe for storage.
	fmt.Printf("%s\n", *hashedPassword)
}

func ExampleHashedPassword_Compare() {
	password := []byte("hunter2")
	hashedPassword, err := security.HashPassword(password)
	if err != nil {
		panic(err)
	}

	test1 := hashedPassword.Compare([]byte("hunter1"))
	test2 := hashedPassword.Compare([]byte("hunter2"))
	test3 := hashedPassword.Compare([]byte("hunter3"))

	fmt.Printf("Test 1: %v, Test 2: %v, Test 3: %v\n", test1, test2, test3)

	// output: Test 1: false, Test 2: true, Test 3: false
}
