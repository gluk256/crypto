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
	fmt.Println("xash v.1.0")
	fmt.Println("USAGE: xash [flags]")
	fmt.Println("\t -s secure input standard (default)")
	fmt.Println("\t -x secure input extended")
	fmt.Println("\t -t plain text input")
	fmt.Println("\t -p password mode input")
	fmt.Println("\t -f file name as input")
	fmt.Println("\t -k keccak hash")
	fmt.Println("\t -h help")
}

func readFile(name string) []byte {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		fmt.Printf("Error: can not read file [%s]\n", name)
		os.Exit(0)
	}
	return b
}

func processFlags() {
	if len(os.Args) > 1 {
		flags := os.Args[1]
		if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
			help()
			os.Exit(0)
		}
		extended = strings.Contains(flags, "x")
		keccakHash = strings.Contains(flags, "k")
		plaintext = strings.Contains(flags, "t")
		passwordMode = strings.Contains(flags, "p")
		fileMode = strings.Contains(flags, "f")
	}
}

func main() {
	var src, hash []byte
	defer crutils.AnnihilateData(src)
	processFlags()

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
		hash = keccak.Digest(src, 32)
	} else {
		hash = crutils.Sha2(src)
	}

	fmt.Printf("%x\n", hash)
	crutils.ProveDataDestruction()
}
