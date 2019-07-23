package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var (
	plaintext    bool
	extended     bool
	passwordMode bool
	fileMode     bool
	keccakHash   bool
)

func help() {
	fmt.Println("USAGE: xash [flags]")
	fmt.Println("\t s secure input standard (default)")
	fmt.Println("\t x secure input extended")
	fmt.Println("\t t plain text input")
	fmt.Println("\t p password mode input")
	fmt.Println("\t f file name as input")
	fmt.Println("\t k keccak hash")
	fmt.Println("\t h help")
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
	var src []byte
	if len(os.Args) > 1 {
		flags := os.Args[1]
		if strings.Contains(flags, "h") {
			help()
			return
		}
		if strings.Contains(flags, "?") {
			help()
			return
		}
		if strings.Contains(flags, "x") {
			extended = true
		}
		if strings.Contains(flags, "k") {
			keccakHash = true
		}
		if strings.Contains(flags, "t") {
			plaintext = true
		}
		if strings.Contains(flags, "p") {
			passwordMode = true
		}
		if strings.Contains(flags, "f") {
			fileMode = true
		}
	}

	if passwordMode {
		src = terminal.PasswordModeInput()
	} else if plaintext {
		src = terminal.PlainTextInput()
	} else {
		src = terminal.SecureInput(extended)
	}

	if fileMode {
		src = readFile(string(src))
	}

	if keccakHash {
		hash := keccak.Digest(src, 32)
		fmt.Printf("%x\n", hash)
		crutils.AnnihilateData(hash)
		crutils.Report()
	} else {
		hash := crutils.Sha2(src)
		fmt.Printf("%x\n", hash)
	}
}
