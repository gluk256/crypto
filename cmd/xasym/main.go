package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var remotePeer *ecdsa.PublicKey
var myKey *ecdsa.PrivateKey
var hash2fa []byte

func cleanup() {
	asym.AnnihilatePrivateKey(myKey)
	asym.AnnihilatePubKey(remotePeer)
	crutils.AnnihilateData(hash2fa)
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
	printMyKey()
}

func getText(cmd string, legend string) (text []byte) {
	if strings.Contains(cmd, "s") {
		text = terminal.SecureInput(false)
	} else {
		fmt.Printf("please enter %s: ", legend)
		if strings.Contains(cmd, "p") {
			text = terminal.PasswordModeInput()
		} else {
			text = terminal.PlainTextInput()
		}
	}
	return text
}

func getHexData(legend string) (res []byte) {
	fmt.Printf("please enter %s: ", legend)
	raw := terminal.PlainTextInput()
	res = make([]byte, len(raw)/2)
	_, err := hex.Decode(res, raw)
	crutils.AnnihilateData(raw)
	if err != nil {
		fmt.Printf("Error decoding hex data: %s\n", err.Error())
		return nil
	}
	return res
}

func importPubKey() {
	x := getHexData("public key")
	if x != nil {
		key, err := asym.ImportPubKey(x)
		if err != nil {
			fmt.Printf("Error importing public key: %s\n", err.Error())
		} else {
			remotePeer = key
		}
	}
	crutils.AnnihilateData(x)
}

func importPrivateKey(cmd string) {
	if strings.Contains(cmd, "r") {
		fmt.Println("Wrong flag 'r': random password is not allowed for import")
		return
	}
	if strings.Contains(cmd, "f") {
		load2FA()
	}
	pass := common.GetPassword(cmd)
	for i := 0; i < len(pass) && i < len(hash2fa); i++ {
		pass[i] ^= hash2fa[i]
	}
	raw := keccak.Digest(pass, 32)
	key, err := asym.ImportPrivateKey(raw)
	if err != nil {
		fmt.Printf("Failed to import private key: %s\n", err.Error())
	} else {
		setMyKey(key)
	}
	crutils.AnnihilateData(pass)
	crutils.AnnihilateData(raw)
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

	generateRandomKey()
	defer cleanup()

	if len(flags) > 0 {
		processCommand(flags)
	}

	run()
}

func processDecryption() {
	data := getHexData("data for decryption")
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
	text := getText(cmd, "your text")
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
		data = getHexData("data for signing")
	} else {
		data = getText(cmd, "data for signing")
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
		data = getHexData("data")
	} else {
		data = getText("", "data")
	}
	if data == nil {
		return
	}
	sig = getHexData("signature")
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
