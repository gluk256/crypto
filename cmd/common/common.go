package common

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

// password for xcmd apps should always be 256 bytes
func expand(prev []byte) []byte {
	res := make([]byte, 256)
	for i := 0; i < 256; i++ {
		res[i] = prev[i%len(prev)]
		res[i] += byte(i)
	}
	crutils.AnnihilateData(prev)
	return res
}

func GetPassword(flags string) (res []byte) {
	if strings.Contains(flags, "r") {
		var err error
		res, err = crutils.GenerateRandomPassword(20)
		fmt.Println(string(res))
		if err != nil {
			fmt.Println("======================> WARNING: the data is not entirely random, not safe to use!")
			fmt.Printf("Error: %s\n", err.Error())
			return res
		}
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

	if len(res) == 0 {
		panic("empty password")
	} else if len(res) < 8 {
		//fmt.Println("======================> WARNING: the password is too short, not safe to use!") // todo: uncomment this line
	}

	res = expand(res)
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
		fmt.Print("Please enter file name: ")
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

func LoadCertificate() ([]byte, error) {
	filename := os.Getenv("HOME") + string("/.xcry/certificate")
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("Failed to load data: %s\n", err.Error())
		fmt.Printf("If file [%s] does not exist, please create it with random data.\n", filename)
		return nil, err
	}

	h := keccak.Digest(data, 256)
	return h, nil
}

func ImportPrivateKey(cmd string) (key *ecdsa.PrivateKey, err error) {
	if strings.Contains(cmd, "r") {
		s := string("Wrong flag 'r': random password is not allowed for private key import")
		fmt.Println(s)
		return nil, errors.New(s)
	}
	var hash2fa []byte
	if strings.Contains(cmd, "f") {
		hash2fa, err = LoadCertificate()
		if err != nil {
			return nil, err
		}
	}
	pass := GetPassword(cmd)
	for i := 0; i < len(pass) && i < len(hash2fa); i++ {
		pass[i] ^= hash2fa[i]
	}
	raw := keccak.Digest(pass, 32)
	key, err = asym.ImportPrivateKey(raw)
	crutils.AnnihilateData(pass)
	crutils.AnnihilateData(raw)
	if err != nil {
		fmt.Printf("Failed to import private key: %s\n", err.Error())
	}
	return key, err
}

func PrintPublicKey(k *ecdsa.PublicKey) {
	pub, err := asym.ExportPubKey(k)
	if err != nil {
		fmt.Printf("Failed to export public key: %s", err.Error())
	} else {
		fmt.Printf("public key: %x\n", pub)
	}
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

func ImportPubKey() (key *ecdsa.PublicKey, raw []byte, err error) {
	raw = GetHexData("public key")
	if raw != nil {
		key, err = asym.ImportPubKey(raw)
		if err != nil {
			fmt.Printf("Error importing public key: %s\n", err.Error())
		}
	} else {
		info := string("wrong input")
		fmt.Println(info)
		err = errors.New(info)
	}
	return key, raw, err
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
