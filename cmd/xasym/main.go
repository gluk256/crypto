package main

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"

	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var remotePeer *ecdsa.PublicKey
var myKey *ecdsa.PrivateKey

func cleanup() {
	asym.AnnihilatePrivateKey(myKey)
	asym.AnnihilatePubKey(remotePeer)
}

func generateRandomKey() {
	k, err := asym.GenerateKey()
	if err != nil {
		fmt.Printf("Failed to generate private key: %s\n", err.Error())
	} else {
		setMyKey(k)
	}
}

func setMyKey(key *ecdsa.PrivateKey) {
	if myKey != nil {
		asym.AnnihilatePrivateKey(myKey)
	}
	myKey = key
	common.PrintPublicKey(&myKey.PublicKey)
}

func importPrivateKey(cmd string) {
	key, err := common.ImportPrivateKey(cmd)
	if err != nil {
		setMyKey(key)
	}
}

func importPubKey() {
	key, _, err := common.ImportPubKey()
	if err != nil {
		remotePeer = key
	}
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
	}

	generateRandomKey()
	defer cleanup()

	if len(flags) > 0 {
		processCommand(flags)
	}

	run()
}

func processDecryption() {
	data := common.GetHexData("data for decryption")
	if data == nil {
		return
	}

	res, err := asym.Decrypt(myKey, data)
	if err != nil {
		fmt.Printf("Error: decryption failed: %s\n", err.Error())
		return
	}

	if common.IsAscii(res) {
		fmt.Printf("Decrypted text: [%s]\n", string(res))
	} else {
		fmt.Printf("Decrypted binary data: [%x]\n", res)
	}

	crutils.AnnihilateData(res)
}

func processEncryption(cmd string) {
	text := common.GetText(cmd, "your text")
	if remotePeer == nil {
		importPubKey()
	}
	res, err := asym.Encrypt(remotePeer, text)
	if err != nil {
		fmt.Printf("Error: encryption failed: %s\n", err.Error())
	} else {
		fmt.Printf("%x\n", res)
	}

	crutils.AnnihilateData(text)
}

func sign(cmd string, hexadecimal bool) {
	var data []byte
	if hexadecimal {
		data = common.GetHexData("data for signing")
	} else {
		data = common.GetText(cmd, "data for signing")
	}
	if data == nil {
		return
	}

	sig, err := asym.Sign(myKey, data)
	if err != nil {
		fmt.Printf("Error: signing failed: %s\n", err.Error())
	} else {
		fmt.Printf("signature: %x\n", sig)
	}

	crutils.AnnihilateData(data)
}

func verify(hexadecimal bool) {
	var data, sig []byte
	if hexadecimal {
		data = common.GetHexData("data")
	} else {
		data = common.GetText("", "data")
	}
	if data == nil {
		return
	}
	sig = common.GetHexData("signature")
	if sig == nil {
		return
	}
	pub, err := asym.SigToPub(data, sig)
	if err != nil {
		fmt.Printf("Failed to retrieve the signature: %s\n", err.Error())
	} else {
		fmt.Printf("public key: %x\n", pub)
	}

	crutils.AnnihilateData(data)
}
