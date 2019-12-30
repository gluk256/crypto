package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
)

func help() {
	fmt.Printf("xquick v.0.%d \n", crutils.CipherVersion)
	fmt.Println("encrypt/decrypt a [big] file with stream cipher (xor only)")
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
	if len(os.Args) > 1 {
		flags = os.Args[1]
		if strings.Contains(flags, "h") || strings.Contains(flags, "?") {
			help()
			return zero, zero, zero
		}
	}

	if len(os.Args) != 4 {
		fmt.Println("ERROR: wrong number of parameters.")
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

	return flags, os.Args[2], os.Args[3]
}

func main() {
	flags, srcFile, dstFile := processCommandArgs()
	if len(flags) != 0 {
		defer crutils.ProveDataDestruction()
		run(flags, srcFile, dstFile)
	}
}

func run(flags string, srcFile string, dstFile string) {
	var err error
	data := loadDataFromFile(flags, srcFile)
	if len(data) == 0 {
		return
	}

	key := common.GetPassword(flags)
	defer crutils.AnnihilateData(key) // in case of panic

	if strings.Contains(flags, "e") {
		data, err = crutils.EncryptQuick(key, data)
	} else {
		data, err = crutils.DecryptQuick(key, data)
	}
	crutils.AnnihilateData(key)

	if err == nil {
		common.SaveData(dstFile, data)
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
		fmt.Printf("The data is too small for decryption [%d bytes]\n", len(data))
		return nil
	}

	return data
}
