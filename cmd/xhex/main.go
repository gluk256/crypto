package main

import (
	"os"
	"fmt"
	"strings"

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
	crutils.EncryptInplaceLevelZero(pass, b)
	crutils.AnnihilateData(pass)
	fmt.Printf("%x\n", b)
}

func getPassword(randpass, secure bool) []byte {
	var res []byte
	if randpass {
		res = crutils.GenerateRandomPassword(16)
		fmt.Println(string(res))
	} else if secure {
		res = terminal.SecureInput(false)
	} else {
		fmt.Print("please enter the password: ")
		res = terminal.PasswordModeInput()
	}
	return res
}
