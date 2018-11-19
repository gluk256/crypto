package main

import (
	"fmt"
	"os"
	"io/ioutil"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/algo/keccak"
)

func help() {
	fmt.Println("USAGE: xash [arg1] [arg2]")
	fmt.Println("\t arg1:")
	fmt.Println("\t\t s secure input standard")
	fmt.Println("\t\t e secure input extended")
	fmt.Println("\t\t t plain text input")
	fmt.Println("\t\t p password mode input")
	fmt.Println("\t\t f file name as input")
	fmt.Println("\t\t x scrambled file name as input")
	fmt.Println("\t\t h help")
	fmt.Println("\t arg2:")
	fmt.Println("\t\t k keccak hash")
	fmt.Println("\t default:")
	fmt.Println("\t\t secure input standard")
}

func readFile(name string) []byte {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		fmt.Printf("Error: can not read file [%s]\n", name)
		os.Exit(0)
	}
	return b
}

func main() {
	var txt []byte
	if len(os.Args) < 2 {
		txt = terminal.SecureInput(false)
	} else if os.Args[1] == "f" {
		txt = terminal.PlainTextInput()
		txt = readFile(string(txt))
	} else if os.Args[1] == "x" {
		txt = terminal.SecureInput(true)
		txt = readFile(string(txt))
	} else if os.Args[1] == "s" {
		txt = terminal.SecureInput(false)
	} else if os.Args[1] == "e" {
		txt = terminal.SecureInput(true)
	} else if os.Args[1] == "h" {
		help()
	} else if os.Args[1] == "?" {
		help()
	} else if os.Args[1] == "t" {
		txt = terminal.PlainTextInput()
	} else if os.Args[1] == "p" {
		txt = terminal.PasswordModeInput()
	} else {
		txt = terminal.SecureInput(false)
	}

	if len(os.Args) < 3 {
		hash := crutils.Sha2(txt)
		fmt.Printf("%x\n", hash)
	} else {
		hash := keccak.Digest(txt, 32)
		fmt.Printf("%x\n", hash)
		crutils.AnnihilateData(hash)
		crutils.ProveDestruction()
	}
}
