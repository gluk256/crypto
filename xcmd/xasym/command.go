package main

import (
	"fmt"
)

func processCommand(cmd string) {
	switch cmd {
	case "h":
		helpInternal()
	case "e":
		processEncryption(cmd)
	case "d":
		processDecryption()
	case "f":
		load2FA()
	case "i":
		importPubKey()
	case "I":
		importPrivateKey(cmd)
	case "r":
		generateRandomKey()
	case "m":
		printMyKey()
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
	fmt.Println("\t -f use a file as two-factor-authentification")
	fmt.Println("\t -i import public key for encryption")
	fmt.Println("\t -I import private key for decryption (from password)")
	fmt.Println("\t -r generate random private key")
	fmt.Println("\t -m print my public key")
	fmt.Println("\t\t -s secure input (only used together with another command)")
	fmt.Println("\t\t -p password mode input (only used together with another command)")
	fmt.Println("\t -h help")
	fmt.Println("\t -q quit")
}
