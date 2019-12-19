package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Printf("xtest v.2.%d \n", crutils.CipherVersion)
	fmt.Println("USAGE: xtxt flag // flag must be a single char")
	fmt.Println("\t -c create a huge file")
	fmt.Println("\t -i run SecureInput")
	fmt.Println("\t -j run SecureInputTest")
	fmt.Println("\t -r generate random passwords")
	fmt.Println("\t -R generate random blob")
	fmt.Println("\t -t ad hoc test")
	fmt.Println("\t -x cryptic exe")
	fmt.Println("\t -X cryptic exe")
	fmt.Println("\t -h help")
}

func crypticExe(secure bool) {
	x := terminal.SecureInput(secure)
	fmt.Println()
	s := strings.Split(string(x), " ")
	cmd := exec.Command(s[0], s[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func main() {
	if len(os.Args) < 2 {
		crypticExe(true)
		return
	}

	// don't remove any functionality from here.
	// for simple ad hoc tests use tst() function.
	switch os.Args[1][0] {
	case '?':
		help()
	case 'c':
		createFile()
	case 'h':
		help()
	case 'i':
		fmt.Println(string(terminal.SecureInput(false)))
	case 'j':
		terminal.SecureInputTest()
	case 'r':
		generateRandomPasswords()
	case 'R':
		generateRandomBlob()
	case 't':
		tst()
	case 'x':
		crypticExe(false)
	case 'X':
		crypticExe(true)
	default:
		if strings.Contains(os.Args[1], "-") {
			fmt.Println("Error: dash is not a valid flag")
		} else {
			fmt.Println("Error: wrong flag")
		}
	}
}

func createFile() {
	name := "mega"
	fmt.Printf("creating file: %s \n", name)
	data := make([]byte, 1024*1024*512)
	err := ioutil.WriteFile(name, data, 0666)
	if err != nil {
		fmt.Printf("Failed to save file: %s \n", err)
	}
}

func generateRandomPasswords() {
	for x := 0; x < 8; x++ {
		s, err := crutils.GenerateRandomPassword(16)
		if err == nil {
			fmt.Println(string(s))
		} else {
			fmt.Printf("Failed to generate random password: %s\n", err.Error())
			break
		}
	}
}

func generateRandomBlob() {
	b := make([]byte, 512)
	err := crutils.StochasticRand(b)
	if err == nil {
		fmt.Printf("%x\n", b)
	} else {
		fmt.Printf("ERROR: %s\n", err)
	}
}

func tst() {
	fmt.Println("test success")
}
