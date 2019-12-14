package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/rcx"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Printf("xquick v.0.%d \n", crutils.CipherVersion)
	fmt.Println("encrypt/decrypt a file with quick cipher (RC4 + AES)")
	fmt.Println("USAGE: xquick flags srcFile dstFile")
	fmt.Println("\t -e encrypt (default mode)")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -r random password")
	fmt.Println("\t -s secure password input")
	fmt.Println("\t -x extra secure password input")
	fmt.Println("\t -h help")
}

func processCommandArgs() (flags string, srcFile string, dstFile string) {
	if len(os.Args) < 2 {
		fmt.Println("ERROR: wrong number of parameters.")
		os.Exit(0)
	}

	flags = os.Args[1]
	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		os.Exit(0)
	}

	if len(os.Args) != 4 {
		fmt.Println("ERROR: wrong number of parameters.")
		os.Exit(0)
	}

	srcFile = os.Args[2]
	dstFile = os.Args[3]

	if strings.Contains(flags, "r") {
		if strings.Contains(flags, "d") {
			fmt.Println("Random password ('r') is incompatible with decryption ('d').")
			fmt.Println("ERROR: wrong flags.")
			os.Exit(0)
		} else if !strings.Contains(flags, "e") {
			flags += "e"
		}
	}

	if !strings.Contains(flags, "e") && !strings.Contains(flags, "d") {
		fmt.Println("ERROR: neither encryption nor decryption specified.")
		os.Exit(0)
	}

	return flags, srcFile, dstFile
}

func deletethis1() { // todo
	fmt.Println("deferrred func 1 exe")
}

func deletethis2() { // todo
	fmt.Println("deferrred func 2 exe")
}

func main() {
	var err error
	flags, srcFile, dstFile := processCommandArgs()
	data := loadDataFromFile(flags, srcFile)
	key := getPassword(flags)

	defer crutils.ProveDataDestruction()
	defer crutils.AnnihilateData(key)
	defer deletethis1()
	defer deletethis2()

	if strings.Contains(flags, "e") {
		data, err = encrypt(key, data)
	} else {
		data, err = decrypt(key, data)
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
		os.Exit(0)
	}

	if strings.Contains(flags, "d") && len(data) <= crutils.EncryptedSizeDiff {
		fmt.Printf("The data is too small for decryption [%d bytes]: %s\n", len(data), err.Error())
		os.Exit(0)
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
	}

	fmt.Println("Failed to save file after max tries. Exit.")
}

func getFileName() string {
	for i := 0; i < 64; i++ {
		fmt.Println("Please enter file name: ")
		f := terminal.PlainTextInput()
		if len(f) == 0 {
			fmt.Println("Error: empty filename, please try again")
		} else if len(f) > 160 {
			fmt.Println("Error: filename too long, please try again")
		} else {
			return string(f)
		}
	}
	fmt.Println("Error: filename input failed. Exit.")
	os.Exit(0)
	return ""
}

func getPassword(flags string) []byte {
	var res []byte
	var err error
	if strings.Contains(flags, "r") {
		res, err = crutils.GenerateRandomPassword(20)
		if err != nil {
			fmt.Printf("Critical error: %s\n", err)
			fmt.Println("Execution aborted")
			os.Exit(0)
		}
		fmt.Println(string(res))
	} else if strings.Contains(flags, "x") {
		res = terminal.SecureInput(true)
	} else if strings.Contains(flags, "s") {
		res = terminal.SecureInput(false)
	} else {
		for len(res) == 0 {
			fmt.Print("please enter the password: ")
			res = terminal.PasswordModeInput()
		}
	}
	return res
}

func encrypt(key []byte, data []byte) ([]byte, error) {
	salt, err := crutils.GenerateSalt()
	if err != nil {
		return nil, err
	}
	keyholder := crutils.GenerateKeys(key, salt)
	defer crutils.AnnihilateData(keyholder)

	rcx.EncryptInplaceRC4(keyholder[crutils.BegRcxKey:crutils.EndRcxKey], data)
	crutils.EncryptInplaceKeccak(keyholder[crutils.BegK1:crutils.EndK1], data)
	data, err = crutils.EncryptAES(keyholder[crutils.BegAesKey:crutils.EndAesKey], salt, data)
	if err == nil {
		data = append(data, salt...)
	}
	return data, err
}

func decrypt(key []byte, data []byte) ([]byte, error) {
	var err error
	salt := data[len(data)-crutils.SaltSize:]
	keyholder := crutils.GenerateKeys(key, salt)
	defer crutils.AnnihilateData(keyholder)

	data, err = crutils.DecryptAES(keyholder[crutils.BegAesKey:crutils.EndAesKey], salt, data)
	if err == nil {
		return data, err
	}

	crutils.EncryptInplaceKeccak(keyholder[crutils.BegK1:crutils.EndK1], data)
	rcx.EncryptInplaceRC4(keyholder[crutils.BegRcxKey:crutils.EndRcxKey], data)
	return data, nil
}
