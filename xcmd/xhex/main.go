package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/rcx"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Println("xhex encrypts/decrypts the given hex string with a password")
	fmt.Println("USAGE: xhex [flags] src")
	fmt.Println("\t r random password")
	fmt.Println("\t s secure password input")
	fmt.Println("\t h help")
}

func main() {
	var src, flags string
	var randpass, secure bool

	if len(os.Args) == 1 {
		help()
		return
	} else if len(os.Args) == 2 {
		src = os.Args[1]
	} else if len(os.Args) == 3 {
		src = os.Args[2]
		flags = os.Args[1]
		randpass = strings.Contains(flags, "r")
		secure = strings.Contains(flags, "s")
		if strings.Contains(flags, "?") || strings.Contains(flags, "h") {
			help()
			return
		}
	} else {
		fmt.Printf("Error: wrong number of arguments [%d]\n", len(os.Args))
		return
	}

	b, err := crutils.HexDecode([]byte(src))
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}
	pass := getPassword(randpass, secure)
	encrypt(pass, b)
	crutils.AnnihilateData(pass)
	fmt.Printf("%x\n", b)
}

func encrypt(key []byte, data []byte) {
	dummy := make([]byte, crutils.DefaultRollover)
	var rc4 rcx.RC4
	rc4.InitKey(key)
	rc4.XorInplace(dummy) // roll forward
	rc4.XorInplace(data)
	crutils.EncryptInplaceKeccak(key, data)
}

func getPassword(randpass, secure bool) []byte {
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
