package main

import (
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
)

func sha2(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
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
	hash := sha2(txt)
	fmt.Printf("%x\n", hash)
}
