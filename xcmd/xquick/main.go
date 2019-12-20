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
	fmt.Printf("xquick v.0.%d \n", crutils.CipherVersion)
	fmt.Println("encrypt/decrypt a [big] file with stream cipher")
	fmt.Println("USAGE: xquick flags srcFile dstFile")
	fmt.Println("\t -e encrypt (default mode)")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -r random password")
	fmt.Println("\t -s secure password input")
	fmt.Println("\t -x extra secure password input")
	fmt.Println("\t -h help")
}

func processCommandArgs() (flags string, srcFile string, dstFile string) {
	var zero string
	if len(os.Args) != 4 {
		fmt.Println("ERROR: wrong number of parameters.")
		return zero, zero, zero
	}

	flags = os.Args[1]
	srcFile = os.Args[2]
	dstFile = os.Args[3]

	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		return zero, zero, zero
	}

	if strings.Contains(flags, "r") {
		if strings.Contains(flags, "d") {
			fmt.Println("Random password ('r') is incompatible with decryption ('d').")
			fmt.Println("ERROR: wrong flags.")
			return zero, zero, zero
		} else if !strings.Contains(flags, "e") {
			flags += "e"
		}
	}

	if !strings.Contains(flags, "e") && !strings.Contains(flags, "d") {
		fmt.Println("ERROR: neither encryption nor decryption specified.")
		return zero, zero, zero
	}

	return flags, srcFile, dstFile
}

func main() {
	defer crutils.ProveDataDestruction()
	flags, srcFile, dstFile := processCommandArgs()
	if len(flags) > 0 {
		run(flags, srcFile, dstFile)
	}
}

func run(flags string, srcFile string, dstFile string) {
	var err error
	data := loadDataFromFile(flags, srcFile)
	if len(data) == 0 {
		return
	}

	key := terminal.GetPassword(flags)
	defer crutils.AnnihilateData(key)

	if strings.Contains(flags, "e") {
		data, err = crutils.EncryptQuick(key, data)
	} else {
		data, err = crutils.DecryptQuick(key, data)
	}

	if err == nil {
		saveData(dstFile, data)
	} else {
		fmt.Printf("ERROR: %s\n", err.Error())
	}
}

func loadDataFromFile(flags string, filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("Failed to load data: %s\n", err.Error())
		return nil
	}

	if strings.Contains(flags, "d") && len(data) <= crutils.EncryptedSizeDiff {
		fmt.Printf("The data is too small for decryption [%d bytes]: %s\n", len(data), err.Error())
		return nil
	}

	return data
}

func saveData(filename string, data []byte) {
	if len(data) == 0 {
		fmt.Println("Error: content is absent, file is not saved.")
		return
	}

	for i := 0; i < 16; i++ {
		err := ioutil.WriteFile(filename, data, 0666)
		if err == nil {
			return
		}

		fmt.Printf("Failed to save file: %s \n", err)
		filename = getFileName()
		if len(filename) == 0 {
			break
		}
	}

	fmt.Println("Failed to save file after max tries. Exit.")
}

func getFileName() string {
	for i := 0; i < 3; i++ {
		fmt.Println("Please enter file name: ")
		f := terminal.PlainTextInput()
		if len(f) == 0 {
			fmt.Println("Error: empty filename, please try again")
		} else if len(f) > 256 {
			fmt.Println("Error: filename too long, please try again")
		} else {
			return string(f)
		}
	}
	fmt.Println("Error: filename input failed.")
	return ""
}
