package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Println("xfile encrypts/decrypts a file (encryption level one)")
	fmt.Println("USAGE: xfile flags srcFile [dstFile]")
	fmt.Println("\t e encrypt")
	fmt.Println("\t d decrypt")
	fmt.Println("\t r random password")
	fmt.Println("\t s secure password input")
	fmt.Println("\t x extra secure password input")
	fmt.Println("\t h help")
}

func getPassword(flags string) []byte {
	var res []byte
	if strings.Contains(flags, "r") {
		res = crutils.RandPass(20)
		fmt.Println(string(res))
	} else if strings.Contains(flags, "s") {
		res = terminal.SecureInput(false)
	} else if strings.Contains(flags, "x") {
		res = terminal.SecureInput(true)
	} else {
		fmt.Print("please enter the password: ")
		res = terminal.PasswordModeInput()
	}
	return res
}

func main() {
	if len(os.Args) < 3 {
		help()
		return
	}

	var dstFile string
	flags := os.Args[1]
	srcFile := os.Args[2]
	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		return
	}

	encrypt := strings.Contains(flags, "e")
	if strings.Contains(flags, "d") {
		encrypt = false
	}

	data := loadFile(srcFile)
	key := getPassword(flags)
	crutils.EncryptInplaceLevelOne(key, data, encrypt)

	if len(os.Args) > 3 {
		dstFile = os.Args[3]
	} else {
		dstFile = getFileName()
	}

	saveData(dstFile, data)
}

func loadFile(fname string) []byte {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		fmt.Printf("Failed to load file: %s \n", err)
		os.Exit(0)
	}
	return data
}

func saveData(filename string, data []byte) {
	if len(data) == 0 {
		fmt.Println("Error: content is absent")
		return
	}

	const ntries = 5
	for i := 0; i < ntries; i++ {
		err := ioutil.WriteFile(filename, data, 0666)
		if err == nil {
			return
		} else {
			fmt.Printf("Failed to save file: %s \n", err)
		}

		filename = getFileName()
		if len(filename) == 0 {
			fmt.Println("Error: empty filename, please try again")
		} else  if len(filename) > 64 {
			fmt.Println("Error: illegal filename. Exit.")
			return
		}
	}

	fmt.Printf("Failed to save file after %d tries. Exit. \n", ntries)
}

func getFileName() string {
	var filename string
	fmt.Println("Enter dst file name: ")
	f := terminal.PlainTextInput()
	if f == nil {
		return ""
	} else {
		filename = string(f)
	}
	return filename
}

