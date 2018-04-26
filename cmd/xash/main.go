package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/crutils"
)

func main() {
	var txt []byte
	if len(os.Args) < 2 {
		txt = terminal.SecureInput()
	} else if os.Args[1] == "p" {
		txt = terminal.StandardInput()
	} else {
		txt = terminal.PasswordModeInput()
	}
	hash := crutils.Sha2(txt)
	fmt.Printf("%x\n", hash)
}
