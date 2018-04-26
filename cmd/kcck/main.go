package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

func main() {
	var proof bool
	var txt []byte
	if len(os.Args) < 2 {
		txt = terminal.SecureInput()
	} else if os.Args[1] == "s" {
		txt = terminal.SecureInput()
		proof = true
	} else if os.Args[1] == "p" {
		txt = terminal.StandardInput()
	} else {
		txt = terminal.PasswordModeInput()
	}

	hash := keccak.Digest(txt, 32)
	fmt.Printf("%x\n", hash)

	crutils.AnnihilateData(hash)
	if proof {
		crutils.ProveDestruction()
	}
}
