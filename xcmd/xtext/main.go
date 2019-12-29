package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/xcmd/common"
)

func help() {
	fmt.Printf("xtxt v.2.%d \n", crutils.CipherVersion)
	fmt.Println("encrypt/decrypt short messages in console")
	fmt.Println("USAGE: xtxt flags [src]")
	fmt.Println("\t -e encrypt")
	fmt.Println("\t -d decrypt")
	fmt.Println("\t -a reveal all decrypted data, including spacing")
	fmt.Println("\t -w use weaker encryption (block cipher without AES, MAC, salt and spacing)")
	fmt.Println("\t -r random password")
	fmt.Println("\t -s secure password input")
	fmt.Println("\t -S secure data input")
	fmt.Println("\t -h help")
}

func processParams() (flags string, data []byte) {
	var zero string
	if len(os.Args) == 2 {
		flags = os.Args[1]
	} else if len(os.Args) == 3 {
		flags = os.Args[1]
		data = []byte(os.Args[2])
	} else {
		flags = "h"
	}

	if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
		help()
		return zero, nil
	}

	if !strings.Contains(flags, "e") && !strings.Contains(flags, "d") {
		if strings.Contains(flags, "r") {
			flags += "e"
		} else if strings.Contains(flags, "a") {
			flags += "d"
		} else {
			fmt.Println("Flags are not clear: encryption or decryption?")
			return zero, nil
		}
	}

	if strings.Contains(flags, "d") {
		if strings.Contains(flags, "r") {
			fmt.Println("Wrong flag 'r': you can not decrypt with random password")
			return zero, nil
		}
		if strings.Contains(flags, "e") {
			fmt.Println("Flags 'e' and 'd' are incompatible: encryption or decryption?")
			return zero, nil
		}
	}

	return flags, data
}

func isWeakerAlgo(flags string, data []byte) bool {
	if strings.Contains(flags, "w") {
		return true
	}

	if strings.Contains(flags, "d") {
		threshold := crutils.MinDataSize*2 + crutils.EncryptedSizeDiff
		if len(data) < threshold {
			return true
		}
	}

	return false
}

func getData(flags string) (data []byte, err error) {
	secure := strings.Contains(flags, "S")
	if secure {
		data = terminal.SecureInput(false)
	} else {
		fmt.Print("please enter the data: ")
		data = terminal.PlainTextInput()
	}
	return data, err
}

func convertData(flags string, data []byte) (res []byte, err error) {
	if strings.Contains(flags, "d") || common.IsHexData(data) {
		h := make([]byte, len(data)/2)
		_, err = hex.Decode(h, data)
		if err != nil {
			fmt.Printf("Error decoding hex data [%d characters]: %s\n", len(data), err.Error())
			return nil, err
		} else {
			res = h
		}
	} else {
		res = data
	}
	return res, nil
}

func main() {
	flags, data := processParams()
	if len(flags) != 0 {
		defer crutils.ProveDataDestruction()
		run(flags, data)
	}
}

func run(flags string, data []byte) {
	var err error
	var res, key, spacing []byte
	if data == nil {
		data, err = getData(flags)
		if err != nil {
			return
		}
	}

	defer crutils.AnnihilateData(data)
	defer crutils.AnnihilateData(res)
	defer crutils.AnnihilateData(spacing)
	defer crutils.AnnihilateData(key) // in case of panic

	data, err = convertData(flags, data)
	if err == nil {
		key = common.GetPassword(flags)
		res, spacing, err = process(flags, key, data)
		crutils.AnnihilateData(key)
		outputResult(flags, err, res, spacing)
	}
}

func process(flags string, key []byte, data []byte) (res []byte, spacing []byte, err error) {
	encryption := strings.Contains(flags, "e")
	if isWeakerAlgo(flags, data) {
		if encryption {
			crutils.EncryptInplaceRCX(key, data)
			crutils.EncryptInplaceKeccak(key, data)
			fmt.Println("Warning: weak encryption used")
		} else {
			crutils.EncryptInplaceKeccak(key, data)
			crutils.DecryptInplaceRCX(key, data)
		}
		res = data
	} else {
		if encryption {
			res, err = crutils.Encrypt(key, data)
		} else {
			res, spacing, err = crutils.Decrypt(key, data)
		}
	}

	return res, spacing, err
}

func outputResult(flags string, err error, res []byte, spacing []byte) {
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	if strings.Contains(flags, "e") { // encryption
		fmt.Printf("%x\n", res)
		return
	}

	if strings.Contains(flags, "a") && spacing != nil {
		fmt.Println("Spacing in hex format:")
		fmt.Printf("%x\n\n", spacing)
	}

	if common.IsAscii(res) {
		fmt.Printf("Decrypted:\n[%s]\n", string(res))
	} else {
		fmt.Printf("Decrypted data in hex format:\n%x\n", res)
	}
}
