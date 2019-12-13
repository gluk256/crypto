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
	fmt.Printf("xhex version 1.%d \n", crutils.Version)
	fmt.Println("encrypt/decrypt short messages from command line")
	fmt.Println("USAGE: xhex [flags] src")
	fmt.Println("\t -e encrypt")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -w weak encryption, resulting in smaller size and no possible errors")
	fmt.Println("\t -r random password")
	fmt.Println("\t -s secure password input")
	fmt.Println("\t -S secure data input")
	fmt.Println("\t -x data in hex format")
	fmt.Println("\t -g reveal the possible steganographic content")
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
		} else {
			fmt.Println("Flags are not clear: encryption or decryption?")
			os.Exit(0)
		}
	}

	if strings.Contains(flags, "x") || strings.Contains(flags, "d") {
		data, err = crutils.HexDecode(data)
		if err != nil {
			fmt.Printf("Error decoding hex data: %s\n", err.Error())
			os.Exit(0)
		}
	}
	return flags, data
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
	process(flags, key, data)

	crutils.AnnihilateData(data)
	crutils.AnnihilateData(key)
	crutils.ProveDataDestruction()
}

func process(flags string, key []byte, data []byte) {
	var err error
	var res, spacing []byte
	weak := strings.Contains(flags, "w")
	encryption := strings.Contains(flags, "e")
	hexadecimal := strings.Contains(flags, "x")
	steg := strings.Contains(flags, "g")

	if weak {
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
			if err == nil && steg {
				fmt.Printf("Spacing: %x\n\n", spacing)
			}
		}
	}

	if err != nil {
		fmt.Printf("Encryption error: %s\n", err.Error())
	} else if encryption || hexadecimal {
		fmt.Printf("%x\n", res)
	} else {
		fmt.Printf("%s\n", string(res))
	}

	crutils.AnnihilateData(res)
	crutils.AnnihilateData(spacing)
}
