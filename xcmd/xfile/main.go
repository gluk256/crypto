package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var stegContent []byte

func help() {
	fmt.Println("xfile encrypts/decrypts a file")
	fmt.Println("USAGE: xfile flags srcFile [dstFile]")
	fmt.Println("\t h help")
	fmt.Println("\t s secure password input")
	fmt.Println("\t S extra secure password input")

	fmt.Println("\t e encrypt")
	fmt.Println("\t\t r random password")
	fmt.Println("\t\t 9 encrypt/decrypt with possible steganographic content")

	fmt.Println("\t d decrypt")
	fmt.Println("\t\t p print decrypted content as text, don't save")
	fmt.Println("\t\t g interactive grep (print specific text lines only)")
	fmt.Println("\t\t G interactive grep with secure input")
	fmt.Println("\t\t x steg")

	fmt.Println("\t x steg")
	fmt.Println("\t y steg secure")
	fmt.Println("\t z steg extra secure")
}

/*
func getEncryptionFlags(flags string) (b byte, steg bool) {
	if strings.Contains(flags, "q") {
		b |= crutils.QuickFlag
	}
	if strings.Contains(flags, "9") {
		b |= crutils.RcxFlag | crutils.AesFlag | crutils.SpacingFlag | crutils.PaddingFlag
		steg = true
	} else if strings.Contains(flags, "6") {
		b |= crutils.RcxFlag | crutils.AesFlag | crutils.SpacingFlag | crutils.PaddingFlag
	} else if strings.Contains(flags, "5") {
		b |= crutils.RcxFlag | crutils.AesFlag | crutils.SpacingFlag
	} else if strings.Contains(flags, "4") {
		b |= crutils.RcxFlag | crutils.AesFlag
	} else if strings.Contains(flags, "3") {
		b |= crutils.AesFlag
	} else if strings.Contains(flags, "2") {
		b |= crutils.RcxFlag | crutils.SpacingFlag
	} else if strings.Contains(flags, "1") {
		b |= crutils.RcxFlag
	} else if strings.Contains(flags, "0") {
		// do nothing
	} else {
		b |= crutils.RcxFlag | crutils.AesFlag | crutils.SpacingFlag | crutils.PaddingFlag // default
	}
	return b, steg
}
*/


// todo: review
func stegDecrypt(key []byte, data []byte) ([]byte, error) {
	_, steg, err := crutils.Decrypt(key, data)
	if err != nil {
		return nil, err
	}

	fmt.Print("please enter the password for steganographic content: ")
	var keySteg []byte
	if strings.Contains(os.Args[1], "S") {
		keySteg = terminal.SecureInput(false)
	} else if strings.Contains(os.Args[1], "X") {
		keySteg = terminal.SecureInput(true)
	} else {
		keySteg = terminal.PasswordModeInput()
	}

	steg, _, err = crutils.DecryptStegContentOfUnknownSize(keySteg, steg)
	return steg, err
}

func getPassword(flags string) []byte {
	var res []byte
	if strings.Contains(flags, "r") {
		res = crutils.GenerateRandomPassword(20)
		fmt.Println(string(res))
	} else if strings.Contains(flags, "s") {
		res = terminal.SecureInput(false)
	} else if strings.Contains(flags, "S") {
		res = terminal.SecureInput(true)
	} else {
		for len(res) == 0 {
			fmt.Print("please enter the password: ")
			res = terminal.PasswordModeInput()
		}
	}
	return res
}

func loadStegContent(plainContent []byte) {
	fmt.Print("please enter the name of file with steganographic content: ")
	filename := terminal.PlainTextInput()
	stegContent = loadFile(string(filename))
	plainSize := primitives.FindNextPowerOfTwo(len(plainContent))
	if plainSize < len(stegContent) + 4 {
		fmt.Printf(">>> Error: plain and steg sizes mismatch [%d vs. %d]\n ", plainSize, len(stegContent) + 4)
		os.Exit(0)
	}
}

func main() {
	var err error
	var res []byte
	var dstFile string
	if len(os.Args) < 3 {
		help()
		return
	}
	cmdFlags := os.Args[1]
	srcFile := os.Args[2]
	if strings.Contains(cmdFlags, "h") || strings.Contains(cmdFlags, "?") {
		help()
		return
	}

	//flags, steg := getEncryptionFlags(cmdFlags)
	steg := strings.Contains(cmdFlags, "x") || strings.Contains(cmdFlags, "X")
	encrypt := strings.Contains(cmdFlags, "e")
	if strings.Contains(cmdFlags, "d") {
		encrypt = false
	}

	data := loadFile(srcFile) // may call os.Exit
	if steg && strings.Contains(cmdFlags, "e") {
		loadStegContent(data) // may call os.Exit
	}
	key := getPassword(cmdFlags)
	if len(key) < 2 {
		fmt.Println(">>> Error: password too short")
		return
	}
	defer func() {
		crutils.AnnihilateData(key)
		crutils.ProveDestruction()
	}()

	if steg {
		if encrypt {
			res, err = crutils.EncryptSteg(key, data, stegContent)
		} else {
			res, err = stegDecrypt(key, data)
		}
	} else {
		if encrypt {
			res, err = crutils.Encrypt(key, data)
		} else {
			res, _, err = crutils.Decrypt(key, data)
		}
	}

	defer crutils.AnnihilateData(res)
	if err != nil {
		fmt.Printf("Error encrypting/decrypting: %s\n", err.Error())
		return
	}
	if !encrypt { // in case of decryption
		if strings.Contains(cmdFlags, "g") || strings.Contains(cmdFlags, "G") {
			runGrep(cmdFlags, res)
			return
		} else if strings.Contains(cmdFlags, "p") {
			fmt.Print(string(res))
			fmt.Println()
			return
		}
	}
	if len(os.Args) > 3 {
		dstFile = os.Args[3]
	}
	saveData(dstFile, res) // may call os.Exit
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

	for i := 0; i < 8; i++ {
		if len(filename) == 0 || i > 0 {
			filename = getFileName()
		}

		err := ioutil.WriteFile(filename, data, 0666)
		if err == nil {
			return
		} else {
			fmt.Printf("Failed to save file: %s \n", err)
		}
	}

	fmt.Println("Failed to save file after max tries. Exit.")
	os.Exit(0)
}

func getFileName() string {
	for i := 0; i < 64; i++ {
		fmt.Println("Enter dst file name: ")
		f := terminal.PlainTextInput()
		if len(f) == 0 {
			fmt.Println("Error: empty filename, please try again")
		} else if len(f) > 80 {
			fmt.Println("Error: filename too long, please try again")
		} else {
			return string(f)
		}
	}
	fmt.Println("Error: filename input failed. Eixt.")
	os.Exit(0)
	return ""
}

func runGrep(flags string, content []byte) {
	lines := strings.Split(string(content), "\n")
	var s []byte
	secure := strings.Contains(flags, "G")
	for {
		fmt.Print("please enter text: ")
		if secure {
			s = terminal.SecureInput(false)
		} else {
			s = terminal.PasswordModeInput()
		}
		if string(s) == "q" {
			break
		}
		found := false
		for _, ln := range lines {
			if strings.Contains(ln, string(s)) {
				fmt.Println(ln)
				found = true
			}
		}
		if !found {
			fmt.Println(">>> Requested text not found")
		}
	}
}
