package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Printf("xtxt v.2.%d \n", crutils.CipherVersion)
	fmt.Println("encrypt/decrypt short messages in console")
	fmt.Println("USAGE: xtxt flags [src]")
	fmt.Println("\t -e encrypt")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -a reveal all decrypted data, including spacing")
	fmt.Println("\t -w use weaker encryption (without AES, MAC, salt and spacing)")
	fmt.Println("\t -r random password")
	fmt.Println("\t -s secure password input")
	fmt.Println("\t -S secure data input")
	fmt.Println("\t -h help")
}

func processParams() (flags string, data []byte) {
	var zero string
	var err error
	if len(os.Args) == 2 {
		flags = os.Args[1]
	} else if len(os.Args) == 3 {
		flags = os.Args[1]
		data = []byte(os.Args[2])
	} else {
		flags = "h"
	}

	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		return zero, nil
	}

	if !strings.Contains(flags, "e") && !strings.Contains(flags, "d") {
		if strings.Contains(flags, "r") {
			flags += "e"
		} else if strings.Contains(flags, "a") {
			flags += "d"
		} else {
			fmt.Println("Flags are not clear: encryption or decryption?")
			return zero, nil
		}
	}

	if data == nil {
		data = getData(flags)
	}

	if strings.Contains(flags, "d") || isHexData(data) {
		data, err = crutils.HexDecode(data)
		if err != nil {
			fmt.Printf("Error decoding hex data: %s\n", err.Error())
			return zero, nil
		}
	}
	return flags, data
}

func isHexData(data []byte) bool {
	for _, c := range data {
		if !strings.ContainsRune(string("0123456789abcdef"), rune(c)) {
			return false
		}
	}
	return true
}

func isAscii(data []byte) bool {
	for _, c := range data {
		if c < 32 { // ignore c > 127 (could be some other alphabet encoding)
			return false
		}
	}
	return true
}

func isWeakerAlgo(flags string, data []byte) bool {
	if strings.Contains(flags, "w") {
		return true
	}

	threshold := crutils.MinDataSize*2 + crutils.EncryptedSizeDiff
	if strings.Contains(flags, "d") && len(data) < threshold {
		return true
	}

	return false
}

func getData(flags string) (res []byte) {
	secure := strings.Contains(flags, "S")
	if secure {
		res = terminal.SecureInput(false)
	} else {
		fmt.Print("please enter the data: ")
		res = terminal.PlainTextInput()
	}
	return res
}

func main() {
	defer crutils.ProveDataDestruction()
	flags, data := processParams()
	if len(flags) > 0 {
		run(flags, data)
	}
}

func run(flags string, data []byte) {
	var err error
	var res, key, spacing []byte
	defer crutils.AnnihilateData(data)
	defer crutils.AnnihilateData(res)
	defer crutils.AnnihilateData(key)
	defer crutils.AnnihilateData(spacing)

	key = terminal.GetPassword(flags)
	res, spacing, err = process(flags, key, data)
	outputResult(flags, err, res, spacing)
}

func process(flags string, key []byte, data []byte) (res []byte, spacing []byte, err error) {
	encryption := strings.Contains(flags, "e")
	if isWeakerAlgo(flags, data) {
		if encryption {
			crutils.EncryptInplaceRCX(key, data)
			crutils.EncryptInplaceKeccak(key, data)
		} else {
			crutils.EncryptInplaceKeccak(key, data)
			crutils.DecryptInplaceRCX(key, data)
		}
		res = data
	} else {
		if encryption {
			res, err = crutils.Encrypt(key, data)
		} else {
			res, spacing, err = crutils.Decrypt(key, data)
		}
	}

	return res, spacing, err
}

func outputResult(flags string, err error, res []byte, spacing []byte) {
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	if strings.Contains(flags, "e") { // encryption
		fmt.Printf("%x\n", res)
		return
	}

	if strings.Contains(flags, "a") && spacing != nil {
		fmt.Println("Spacing in hex format:")
		fmt.Printf("%x\n\n", spacing)
	}

	if isAscii(res) {
		fmt.Printf("%s\n", string(res))
	} else {
		fmt.Printf("Decrypted data in hex format:\n%x\n", res)
	}
}
