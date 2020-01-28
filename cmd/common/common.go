package common

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func GetPassword(flags string) (res []byte) {
	if strings.Contains(flags, "r") {
		var err error
		res, err = crutils.GenerateRandomPassword(20)
		fmt.Println(string(res))
		if err != nil {
			fmt.Println("====================> WARNING: the data is not entirely random, not safe to use!")
			fmt.Printf("Error: %s\n", err.Error())
			return res
		}
	} else if strings.Contains(flags, "x") {
		fmt.Println()
		res = terminal.SecureInput(true)
	} else if strings.Contains(flags, "s") {
		fmt.Println()
		res = terminal.SecureInput(false)
	} else {
		for len(res) == 0 {
			fmt.Print("please enter the password: ")
			res = terminal.PasswordModeInput()
		}
	}

	// if len(res) == 0 {
	// 	panic("empty password")
	// }

	if len(res) < 4 {
		fmt.Println("====================> WARNING: the password is too short, not safe to use!")
	}

	res = keccak.Digest(res, 256) // the keys for all crypto apps must always be 256 bytes
	return res
}

func IsAscii(data []byte) bool {
	for _, c := range data {
		if c < 32 { // ignore c > 127 (could be some other alphabet encoding)
			return false
		}
	}
	return true
}

func IsHexData(data []byte) bool {
	for _, c := range data {
		if !strings.ContainsRune(string("0123456789abcdef"), rune(c)) {
			return false
		}
	}
	return true
}

func GetFileName() string {
	for i := 0; i < 3; i++ {
		fmt.Print("please enter file name: ")
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

func SaveData(filename string, data []byte) error {
	if len(data) == 0 {
		fmt.Println("Error: content is absent, file is not saved.")
		return errors.New("empty data")
	}

	for i := 0; i < 16; i++ {
		if len(filename) == 0 || i > 0 {
			filename = GetFileName()
			if len(filename) == 0 || filename == string("q") {
				break
			}
		}

		err := ioutil.WriteFile(filename, data, 0666)
		if err == nil {
			return nil
		} else {
			fmt.Printf("Failed to save file: %s \n", err)
		}
	}

	fmt.Println("Failed to save file after max tries. Exit.")
	return errors.New("max tries exceeded")
}

func GetCryptoDir() (dir string, exist bool) {
	dir = os.Getenv("HOME")
	if len(dir) != 0 {
		dir += string("/.xcry")
		_, err := os.Stat(dir)
		exist = (err == nil)
	}
	return dir, exist
}

func GetFullFileName(name string) string {
	dir, _ := GetCryptoDir()
	return dir + "/" + name
}

func LoadCertificate(retry bool) ([]byte, error) {
	fullname := GetFullFileName("certificate")
	data, err := ioutil.ReadFile(fullname)
	if err != nil && !retry {
		fmt.Printf("Failed to load data: %s\n", err.Error())
		fmt.Printf("If file [%s] does not exist, please create it with random data.\n", fullname)
		return nil, err
	}

	for err != nil {
		fmt.Print("Loading certificate, ")
		filename := GetFileName()
		if filename == "q" {
			return nil, errors.New("quit cmd received")
		}
		data, err = ioutil.ReadFile(filename)
		if err != nil {
			fmt.Printf("Failed to load data: %s\n", err.Error())
		}
	}

	h := keccak.Digest(data, 256)
	return h, nil
}

func GetText(cmd string, legend string) (text []byte) {
	if strings.Contains(cmd, "s") {
		text = terminal.SecureInput(false)
	} else {
		fmt.Printf("please enter %s: ", legend)
		if strings.Contains(cmd, "p") {
			text = terminal.PasswordModeInput()
		} else {
			text = terminal.PlainTextInput()
		}
	}
	return text
}

func GetUint(legend string) (uint32, error) {
	fmt.Printf("please enter %s: ", legend)
	t := terminal.PlainTextInput()
	res, err := strconv.ParseUint(string(t), 0, 32)
	return uint32(res), err
}

func GetHexData(legend string) (res []byte) {
	fmt.Printf("please enter %s: ", legend)
	raw := terminal.PlainTextInput()
	res = make([]byte, len(raw)/2)
	_, err := hex.Decode(res, raw)
	crutils.AnnihilateData(raw)
	if err != nil {
		fmt.Printf("Error decoding hex data: %s\n", err.Error())
		return nil
	}
	return res
}

func Confirm(question string) bool {
	fmt.Printf("%s [y/n] ", question)
	s := terminal.PlainTextInput()
	if s == nil {
		return false
	}
	answer := string(s)
	return (answer == "y" || answer == "yes")
}
