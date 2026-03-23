// 文件路径: cmd/builder/main.go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/GoShield/internal/compiler"
	"github.com/yourusername/GoShield/internal/crypto"
)

func main() {
	var inputFile string
	var outputFile string

	flag.StringVar(&inputFile, "i", "", "Input: Original EXE path (e.g., app.exe)")
	flag.StringVar(&outputFile, "o", "Protected.exe", "Output: Protected EXE path")
	flag.Parse()

	if inputFile == "" {
		fmt.Println("Error: Input file is required.")
		fmt.Println("Usage: builder.exe -i <original.exe> [-o <protected.exe>]")
		os.Exit(1)
	}

	fmt.Println("[*] Reading original executable...")
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("[-] Failed to read file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Generating 256-bit AES encryption key...")
	key, err := crypto.GenerateRandomKey()
	if err != nil {
		fmt.Printf("[-] Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Encrypting and packing payload...")
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		fmt.Printf("[-] Encryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Compiling protected stub (Requires Go toolchain)...")
	err = compiler.BuildProtectedExe(ciphertext, key, outputFile)
	if err != nil {
		fmt.Printf("[-] Build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Success! Protected executable saved to: %s\n", outputFile)
}
