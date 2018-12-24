package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
	"io/ioutil"
)

func help() {
	fmt.Println("USAGE: kcck [arg]")
	fmt.Println("\t e secure input extended")
	fmt.Println("\t t plain text input")
	fmt.Println("\t p password mode input")
	fmt.Println("\t f file name as input")
	fmt.Println("\t x scrambled file name as input")
	fmt.Println("\t h help")
	fmt.Println("\t [no_param] secure input standard")
	fmt.Println("\t [default] secure input standard")
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
	var data []byte
	if len(os.Args) < 2 {
		data = terminal.SecureInput(false)
	} else if os.Args[1] == "f" {
		data = terminal.PlainTextInput()
		data = readFile(string(data))
	} else if os.Args[1] == "x" {
		data = terminal.SecureInput(true)
		data = readFile(string(data))
	} else if os.Args[1] == "e" {
		data = terminal.SecureInput(true)
	} else if os.Args[1] == "h" {
		help()
	} else if os.Args[1] == "?" {
		help()
	} else if os.Args[1] == "t" {
		data = terminal.PlainTextInput()
	} else if os.Args[1] == "p" {
		data = terminal.PasswordModeInput()
	} else {
		data = terminal.SecureInput(false)
	}

	hash := keccak.Digest(data, 32)
	fmt.Printf("%x\n", hash)

	crutils.AnnihilateData(data)
	crutils.ProveDestruction()
}
