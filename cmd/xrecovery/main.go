package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var Delimiter = "————————————————————————————————————————————————————————————————————————————————————————————————————"

func help() {
	fmt.Printf("xrecovery v.3.%d.0.2 (C) 2026 \n", crutils.CipherVersion)
	fmt.Println("recovers content in case of corrupted password (assuming only one char is corrupted)")
	fmt.Println("USAGE: xrecovery flags srcFile")
	fmt.Println("\t -p linux-style password input")
	fmt.Println("\t -s secure password/text input")
	fmt.Println("\t -x extra secure password/text input")
	fmt.Println("\t -u unknown size")
	fmt.Println("\t -q quick encryption mode")
	fmt.Println("\t -c [linux-style 'cat' cmd] output decrypted content")
	fmt.Println("\t -f save face to file")
	fmt.Println("\t -F save encrypted steg to file")
}

func main() {
	if len(os.Args) < 3 {
		help()
		return
	}

	flags := os.Args[1]
	srcFile := os.Args[2]
	data, err := os.ReadFile(srcFile)
	if err != nil {
		fmt.Printf("Failed to load data: %s\n", err.Error())
		return
	}
	if len(data) == 0 {
		fmt.Println("Failed to load data: the file is empty")
		return
	}
	if len(data) <= crutils.SaltSize {
		// we need this check here because decryption errors are ignored in recovery mode
		fmt.Printf("data size (%d bytes), less than salt size (%d bytes)", len(data), crutils.SaltSize)
		return
	}

	defer crutils.ProveDataDestruction()
	defer crutils.AnnihilateData(data)

	quick := strings.Contains(flags, "q")
	unknownSize := strings.Contains(flags, "u")
	recover(flags, data, quick, unknownSize)
}

func recover(flags string, data []byte, quick bool, unknownSize bool) {
	var err error
	var key, decrypted, steg []byte
	defer crutils.AnnihilateData(key)
	defer crutils.AnnihilateData(decrypted)
	defer crutils.AnnihilateData(steg)

	key, err = common.GetPasswordRaw(flags)
	if err == nil {
		decrypted, steg, err = tryAllKeys(flags, key, data, quick, unknownSize)
	}
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if strings.Contains(flags, "c") {
		fmt.Printf("%s\n%s\n%s\n", Delimiter, string(decrypted), Delimiter)
	}

	if strings.Contains(flags, "f") && len(decrypted) > 0 {
		fmt.Println("saving decrypted face content...")
		common.SaveData("", decrypted)
	}
	if strings.Contains(flags, "F") && len(steg) > 0 {
		fmt.Println("saving encrypted steg content...")
		common.SaveData("", steg)
	}

	if !quick && len(steg) > 0 {
		repeat := common.Confirm("Do you want to decrypt the steg content as well?")
		if repeat {
			recover(flags, steg, quick, true)
		}
	}
}

func tryAllKeys(flags string, key []byte, data []byte, quick bool, unknownSize bool) (decrypted []byte, steg []byte, err error) {
	k := keccak.Digest(key, 256)
	decrypted, steg, err = decrypt(k, data, quick, unknownSize)
	if err == nil {
		fmt.Println("Decrypted successfuly with original key")
		return decrypted, steg, err
	}

	for i := 0; i < len(key); i++ {
		k := getExpandedKeyWithMissingChar(key, i)
		decrypted, steg, err = decrypt(k, data, quick, unknownSize)
		if err == nil {
			fmt.Printf("Decrypted successfuly, char %d was missing \n", i)
			return decrypted, steg, err
		}
	}

	alphabet := terminal.AlphabetStandard
	if strings.Contains(flags, "x") {
		alphabet = terminal.AlphabetExt
	}

	for i := 0; i < len(key); i++ {
		for j := 0; j < len(alphabet); j++ {
			k := getExpandedKeyWithChangedChar(key, i, alphabet[j])
			decrypted, steg, err = decrypt(k, data, quick, unknownSize)
			if err == nil {
				offset := j - strings.Index(string(alphabet), string(key[i:i+1]))
				fmt.Printf("Decrypted successfuly, char %d offset: %d [of %d] \n", i, offset, len(alphabet))
				return decrypted, steg, err
			}
		}
	}

	return nil, nil, errors.New("Brute force recovery failed. Maybe more than one char is corrupted.")
}

func decrypt(key []byte, data []byte, quick bool, unknownSize bool) (decrypted []byte, steg []byte, err error) {
	d := make([]byte, len(data))
	copy(d, data)

	if quick {
		decrypted, err = crutils.DecryptQuick(key, d)
	} else if unknownSize {
		decrypted, steg, err = crutils.DecryptStegContentOfUnknownSize(key, d)
	} else {
		decrypted, steg, err = crutils.Decrypt(key, d)
	}
	return decrypted, steg, err
}

func getExpandedKeyWithMissingChar(key []byte, i int) []byte {
	res := make([]byte, len(key)-1)
	copy(res, key[:i])
	copy(res[i:], key[i+1:])
	res = keccak.Digest(res, 256)
	return res
}

func getExpandedKeyWithChangedChar(key []byte, i int, c byte) []byte {
	res := make([]byte, len(key))
	copy(res, key)
	res[i] = c
	res = keccak.Digest(res, 256)
	return res
}
