package main

import (
	"fmt"

	"github.com/gluk256/crypto/cmd/common"
)

func processCommand(cmd string) {
	if len(cmd) == 0 {
		fmt.Println(">>> Error: empty command")
	}

	switch cmd[0] {
	case 'h':
		helpInternal()
	case 'e':
		processEncryption(cmd)
	case 'd':
		processDecryption()
	case 'i':
		importPubKey()
	case 'I':
		importPrivateKey(cmd)
	case 'r':
		generateRandomKey()
	case 'k':
		common.PrintPublicKey(&myKey.PublicKey)
	case 't':
		sign(cmd, false)
	case 'b':
		sign(cmd, true)
	case 'v':
		verify(false)
	case 'w':
		verify(true)
	default:
		fmt.Printf(">>> Wrong command: %s \n", cmd)
	}
}

func help() {
	fmt.Println("xasym v.0")
	fmt.Println("elliptic curve cryptography in console")
	fmt.Println("USAGE: xasym flags")
	helpInternal()
}

func helpInternal() {
	fmt.Println("\t -e encrypt")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -i import public key for encryption")
	fmt.Println("\t -I import private key for decryption (from password)")
	fmt.Println("\t\t -s secure input (only used together with another command)")
	fmt.Println("\t\t -p password mode input (only used together with another command)")
	fmt.Println("\t\t -f use a file as two-factor-authentification")
	fmt.Println("\t -r generate random private key")
	fmt.Println("\t -k print my public key")
	fmt.Println("\t -t sign text")
	fmt.Println("\t -b sign binary data in hexadecimal representation")
	fmt.Println("\t -v verify signature")
	fmt.Println("\t -w verify signature of binary data in hexadecimal representation")
	fmt.Println("\t -h help")
	fmt.Println("\t -q quit")
}
