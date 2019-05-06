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

func help() {
	fmt.Println("xfile encrypts/decrypts a file")
	fmt.Println("USAGE: xfile [flags] [srcFile] [dstFile]")
	fmt.Println("\t h help")
	fmt.Println("\t s secure password input")
	fmt.Println("\t x extra secure password input")
	fmt.Println("\t f save to file")

	fmt.Println("\t e encrypt (default mode)")
	fmt.Println("\t\t r random password")

	fmt.Println("\t d decrypt")
	fmt.Println("\t\t p print decrypted content as text, don't save")
	fmt.Println("\t\t g interactive grep (print specific text lines only)")
	fmt.Println("\t\t G interactive grep with secure input")

	fmt.Println("\t l load file")
	fmt.Println("\t\t i insert file content into another file as steganographic content")
}

func processCommandArgs() (flags string, srcFile string, dstFile string) {
	if len(os.Args) > 1 {
		flags = os.Args[1]
	}
	if len(os.Args) > 2 {
		srcFile = os.Args[2]
	}
	if len(os.Args) > 3 {
		dstFile = os.Args[3]
	}

	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		os.Exit(0)
	}

	if strings.Contains(flags, "d") && strings.Contains(flags, "r") {
		fmt.Println("Random password ('r') is incompatible with decryption ('d').")
		fmt.Println("FATAL ERROR: wrong flags. Exit.")
		os.Exit(0)
	}

	return flags, srcFile, dstFile
}

func main() {
	flags, srcFile, dstFile := processCommandArgs()
	if strings.Contains(flags, "d") {
		data := loadDataFromFile(srcFile, crutils.MinDataSize + crutils.EncryptedSizeDiff)
		processDecryption(flags, data, dstFile, false)
	} else if strings.Contains(flags, "e") {
		processEncryption(flags, srcFile, dstFile, nil)
	} else {
		loadFile(flags, srcFile, dstFile)
	}
}

func loadFile(flags string, srcFile string, dstFile string) {
	data := loadDataFromFile(srcFile, 0) // may call os.Exit
	fmt.Print("What do you want to do with loaded content? Please enter the command [ied]: ")
	cmd := string(terminal.PlainTextInput())
	if strings.Contains(cmd, "d") {
		processDecryption(flags, data, dstFile, false)
	} else if strings.Contains(cmd, "e") {
		processEncryption(flags, srcFile, dstFile, nil)
	} else if strings.Contains(cmd, "i") {
		processEncryption(flags, "", dstFile, data)
	} else {
		fmt.Println("Wrong command. Exit.")
	}
}

func decrypt(flags string, data []byte, unknownSize bool) (decrypted []byte, steg []byte, err error) {
	for {
		key := getPassword(flags)
		if unknownSize {
			decrypted, steg, err = crutils.DecryptStegContentOfUnknownSize(key, data)
		} else {
			decrypted, steg, err = crutils.Decrypt(key, data)
		}
		crutils.AnnihilateData(key)
		if err == nil {
			return decrypted, steg, err
		}
		fmt.Printf("Failed to decrypt data: %s\n", err.Error())
		fmt.Print("Do you want to retry? [y/n]: ")
		res := terminal.PlainTextInput()
		if len(res) > 0 && res[0] == 'n' {
			return nil, nil, err
		}
	}
	return decrypted, steg, err
}

func processDecryption(flags string, data []byte, dstFile string, unknownSize bool) {
	decrypted, steg, err := decrypt(flags, data, unknownSize)
	if err != nil {
		return
	}

	if !strings.Contains(flags, "f") {
		fmt.Print("What do you want to do with decrypted content? Please enter the command [Ggpsxfd]: ")
		flags = string(terminal.PlainTextInput())
	}

	if strings.Contains(flags, "f") {
		saveData(dstFile, decrypted)
	} else if strings.Contains(flags, "G") {
		runGrep(flags, decrypted)
	} else if strings.Contains(flags, "g") {
		runGrep(flags, decrypted)
	} else if strings.Contains(flags, "p") {
		fmt.Print(string(decrypted))
		fmt.Println()
	} else {
		processDecryption(flags, steg, dstFile, true) // recursively decrypt steg content
	}

	crutils.AnnihilateData(decrypted)
	crutils.AnnihilateData(steg)
}

func encrypt(key []byte, data []byte, steg []byte) ([]byte, error) {
	if steg == nil {
		return crutils.Encrypt(key, data)
	} else {
		return crutils.EncryptSteg(key, data, steg)
	}
}

func processEncryption(flags string, srcFile string, dstFile string, steg []byte) {
	data := loadDataFromFile(srcFile, len(steg)) // may call os.Exit
	key := getPassword(flags)
	encrypted, err := encrypt(key, data, steg)
	crutils.AnnihilateData(key)
	if err != nil {
		fmt.Printf("Failed to encrypt data: %s\nFATAL ERROR. Exit.\n", err.Error())
		os.Exit(0)
	}

	if !strings.Contains(flags, "f") {
		fmt.Print("What do you want to do with encrypted content? Please enter the command [rsxfe]: ")
		flags = string(terminal.PlainTextInput())
	}

	if strings.Contains(flags, "f") {
		saveData(dstFile, encrypted)
	} else {
		processEncryption(flags, "", dstFile, encrypted) // recursively encrypt steg content
	}

	crutils.AnnihilateData(data)
	crutils.AnnihilateData(steg)
}

func loadDataFromFile(filename string, minSize int) []byte {
	for i := 0; i < 64; i++ {
		if len(filename) == 0 || i > 0 {
			filename = getFileName() // may call os.Exit
		}
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Printf("Failed to load data: %s\n", err.Error())
			fmt.Println("Please try again.")
			continue
		}
		expanded := primitives.FindNextPowerOfTwo(len(data))
		if expanded < minSize {
			fmt.Printf("The data size %d (padded: %d) is less than required size %d\n", len(data), expanded, minSize)
			fmt.Println("Please try again.")
			continue
		}
		return data
	}

	fmt.Println("The number of iterations exceeded allowed maximum. Exit.")
	os.Exit(0)
	return nil
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
	fmt.Println("Error: filename input failed. Eixt.")
	os.Exit(0)
	return ""
}

func saveData(filename string, data []byte) {
	if len(data) == 0 {
		fmt.Println("Error: content is absent, file is not saved.")
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

func getPassword(flags string) []byte {
	var res []byte
	if strings.Contains(flags, "r") {
		res = crutils.GenerateRandomPassword(20)
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
