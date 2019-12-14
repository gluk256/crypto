package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func checkHelp(flags string) {
	if strings.Contains(flags, "?") || strings.Contains(flags, "h") {
		help()
		os.Exit(0)
	}
}

func help() {
	fmt.Printf("xhex v.2.%d \n", crutils.CipherVersion)
	fmt.Println("encrypt/decrypt short messages in console")
	fmt.Println("USAGE: xhex [flags] src")
	fmt.Println("\t -e encrypt")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -a reveal all decrypted data, including spacing")
	fmt.Println("\t -w use weaker encryption (without AES, MAC and salt)")
	fmt.Println("\t -r random password")
	fmt.Println("\t -s secure password input")
	fmt.Println("\t -S secure data input")
	fmt.Println("\t -h help")
}

func processParams() (flags string, data []byte) {
	var err error
	if len(os.Args) == 1 {
		help()
		os.Exit(0)
	} else if len(os.Args) == 2 {
		flags = os.Args[1]
		checkHelp(flags)
		data = getData(flags)
	} else if len(os.Args) == 3 {
		flags = os.Args[1]
		checkHelp(flags)
		data = []byte(os.Args[2])
	} else {
		fmt.Printf("Error: wrong number of arguments [%d]\n", len(os.Args))
		os.Exit(0)
	}

	if !strings.Contains(flags, "e") && !strings.Contains(flags, "d") {
		if strings.Contains(flags, "r") {
			flags += "e"
		} else if strings.Contains(flags, "a") {
			flags += "d"
		} else {
			fmt.Println("Flags are not clear: encryption or decryption?")
			os.Exit(0)
		}
	}

	if strings.Contains(flags, "d") || isHexData(data) {
		data, err = crutils.HexDecode(data)
		if err != nil {
			fmt.Printf("Error decoding hex data: %s\n", err.Error())
			os.Exit(0)
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

func getPassword(flags string) []byte {
	randpass := strings.Contains(flags, "r")
	secure := strings.Contains(flags, "s")

	var res []byte
	var err error
	if randpass {
		res, err = crutils.GenerateRandomPassword(16)
		fmt.Println(string(res))
		if err != nil {
			fmt.Printf("ERROR: %s\n", err)
			fmt.Println("ATTENTION!!! The data is not entirely random. Not safe to use!")
		}
	} else if secure {
		res = terminal.SecureInput(false)
	} else {
		fmt.Print("please enter the password: ")
		res = terminal.PasswordModeInput()
	}

	return res
}

func main() {
	flags, data := processParams()
	key := getPassword(flags)
	res, spacing, err := process(flags, key, data)
	outputResult(flags, err, res, spacing)

	crutils.AnnihilateData(res)
	crutils.AnnihilateData(spacing)
	crutils.AnnihilateData(data)
	crutils.AnnihilateData(key)
	crutils.ProveDataDestruction()
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
		fmt.Printf("Spacing in hex format: %x\n\n", spacing)
	}

	if isHexData(res) {
		fmt.Printf("Decrypted data in hex format:\n%x\n", res)
	} else {
		fmt.Printf("%s\n", string(res))
	}
}
