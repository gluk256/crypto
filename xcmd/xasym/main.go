package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/asym"
	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/xcmd/common"
)

var remotePeer *ecdsa.PublicKey
var myKey *ecdsa.PrivateKey
var hash2fa []byte

func cleanup() {
	asym.AnnihilatePrivateKey(myKey)
	asym.AnnihilatePubKey(remotePeer)
	crutils.AnnihilateData(hash2fa)
}

func initialize() {
	generateRandomKey()
}

func load2FA() {
	filename := common.GetFileName()
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("Failed to load data: %s\n", err.Error())
	} else {
		hash2fa = keccak.Digest(data, 256)
	}
}

func printMyKey() {
	pub, err := asym.ExportPubKey(&myKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to export public key: %s", err.Error())
	} else {
		fmt.Printf("Your public key: %x\n", pub)
	}
}

func generateRandomKey() {
	var err error
	if myKey != nil {
		asym.AnnihilatePrivateKey(myKey)
	}
	myKey, err = asym.GenerateKey()
	if err != nil {
		fmt.Printf("Failed to generate private key: %s\n", err.Error())
	} else {
		printMyKey()
	}
}

func importPubKey() {
	// todo
}

func importPrivateKey() {
	// todo
}

func processEncryptionCmd() {
	// todo
}

func processDecryptionCmd() {
	// todo
}

func run() {
	for {
		fmt.Print("Enter command: ")
		s := terminal.PlainTextInput()
		if s != nil {
			cmd := string(s)
			if cmd == "q" {
				return
			} else {
				processCommand(cmd)
			}
		}
	}
}

func main() {
	var flags string
	if len(os.Args) >= 2 {
		flags = os.Args[1]
		if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
			help()
			return
		} else if strings.Contains(flags, "q") {
			return
		}

		if strings.Contains(flags, "f") {
			load2FA()
		}
	}

	initialize() // todo: maybe refactor this func away (delete)
	defer cleanup()

	if len(flags) > 0 {
		processCommand(flags)
	}

	run()
}
