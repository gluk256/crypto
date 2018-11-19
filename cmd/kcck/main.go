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
	var txt []byte
	if len(os.Args) < 2 {
		txt = terminal.SecureInput(false)
	} else if os.Args[1] == "f" {
		txt = terminal.PlainTextInput()
		txt = readFile(string(txt))
	} else if os.Args[1] == "x" {
		txt = terminal.SecureInput(true)
		txt = readFile(string(txt))
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

	hash := keccak.Digest(txt, 32)
	fmt.Printf("%x\n", hash)

	crutils.AnnihilateData(hash)
	crutils.ProveDestruction()
}

//func main() {
//	var proof bool
//	var txt []byte
//	if len(os.Args) < 2 {
//		txt = terminal.SecureInput(false)
//	} else if os.Args[1] == "s" {
//		txt = terminal.SecureInput(false)
//		proof = true
//	} else if os.Args[1] == "p" {
//		txt = terminal.PlainTextInput()
//	} else {
//		txt = terminal.PasswordModeInput()
//	}
//
//	hash := keccak.Digest(txt, 32)
//	fmt.Printf("%x\n", hash)
//
//	crutils.AnnihilateData(hash)
//	if proof {
//		crutils.ProveDestruction()
//	}
//}
