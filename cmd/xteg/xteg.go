package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Println("xteg encrypts/decrypts a file (encryption level one)")
	fmt.Println("USAGE: xfile flags srcFile [dstFile]")
	fmt.Println("\t e encrypt")
	fmt.Println("\t d decrypt")
	fmt.Println("\t r random password")
	fmt.Println("\t s secure password input")
	fmt.Println("\t x extra secure password input")
	fmt.Println("\t 1 encryption level")
	fmt.Println("\t 2 encryption level")
	fmt.Println("\t 3 encryption level")
	fmt.Println("\t 4 encryption level")
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
		for len(res) == 0 {
			fmt.Print("please enter the password: ")
			res = terminal.PasswordModeInput()
		}
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

	level := getEncryptionLevel(flags)
	encrypt := strings.Contains(flags, "e")
	if strings.Contains(flags, "d") {
		encrypt = false
	}

	data := loadFile(srcFile)
	key := getPassword(flags)
	defer func() {
		crutils.AnnihilateData(key)
		crutils.ProveDestruction()
	}()

	res, err := crypt(key, data, encrypt, level)
	if err != nil {
		fmt.Printf("Error encrypting/decrypting: %s\n", err.Error())
		return
	}

	if len(os.Args) > 3 {
		dstFile = os.Args[3]
	} else {
		dstFile = getFileName()
	}

	saveData(dstFile, res)
}

func crypt(key []byte, data []byte, encrypt bool, level int) ([]byte, error) {
	if level == 0 {
		crutils.EncryptInplaceLevelZero(key, data)
		return data, nil
	} else if level == 1 {
		crutils.EncryptInplaceLevelOne(key, data, encrypt, false)
		return data, nil
	} else if level == 2 {
		return crutils.EncryptLevelThree(key, data, encrypt, false)
	} else if level == 4 {
		return crutils.EncryptLevelFour(key, data, encrypt, false)
	} else {
		return nil, errors.New(fmt.Sprintf("Unknown level %d", level))
	}
}

func getEncryptionLevel(flags string) int {
	if strings.Contains(flags, "0") {
		return 0
	} else if strings.Contains(flags, "1") {
		return 1
	} else if strings.Contains(flags, "2") {
		return 2
	} else if strings.Contains(flags, "3") {
		return 3
	} else if strings.Contains(flags, "4") {
		return 4
	}
	return 2 // default level 2
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

