package main

import (
	"fmt"
	"os"
	"io/ioutil"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/crutils"
)

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
		txt = terminal.SecureInput()
	} else if os.Args[1] == "p" {
		txt = terminal.StandardInput()
	} else {
		txt = terminal.PasswordModeInput()
	}
	//txt = readFile(string(txt))
	hash := crutils.Sha2(txt)
	fmt.Printf("%x\n", hash)
}
