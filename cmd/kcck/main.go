package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

func keccakHash(s []byte) []byte {
	var k keccak.Keccak512
	k.Write(s)
	out := make([]byte, 256)
	k.Read(out)
	return out[:32]

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
	hash := keccakHash(txt)
	fmt.Printf("%x\n", hash)
	crutils.AnnihilateData(hash)
}
