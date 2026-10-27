package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func help() {
	fmt.Printf("xtest v.3.%d.1 (C) 2026 \n", crutils.CipherVersion)
	fmt.Println("This is a helper tool for manual i/o tests")
	fmt.Println("USAGE: xtest flag")
	fmt.Println("\t -e SecureInput echo")
	fmt.Println("\t -i hash (secure input)")
	fmt.Println("\t -I hash (secure extra input)")
	fmt.Println("\t -k run key input test [exit: ctrl+a]")
	fmt.Println("\t -f create a simple file containing text and zeros")
	fmt.Println("\t -r generate random passwords")
	fmt.Println("\t -b generate random blob")
	fmt.Println("\t -t ad hoc test")
	fmt.Println("\t -x exe")
	fmt.Println("\t -X exe ext")
	fmt.Println("\t -h help")
}

func process(f rune) {
	// don't remove any functionality from here. for simple ad hoc tests use tst() function.
	switch f {
	case '?':
		help()
	case 'f':
		createFile()
	case 'h':
		help()
	case 'e':
		fmt.Println(string(terminal.SecureInput(false)))
	case 'i':
		testHash(false)
	case 'I':
		testHash(true)
	case 'k':
		terminal.SecureInputTest()
	case 'r':
		generateRandomPasswords()
	case 'b':
		generateRandomBlob()
	case 't':
		tst()
	case 'x':
		crypticExe(false)
	case 'X':
		crypticExe(true)
	default:
		fmt.Println("Error: wrong flag")
	}
}

func main() {
	var f rune = 'h'
	if len(os.Args) > 1 {
		for _, c := range os.Args[1] {
			if c != '-' {
				f = c
				break
			}
		}
	}

	process(f)
}

func testHash(ext bool) {
	s := terminal.SecureInput(ext)
	hash := crutils.Sha2(s)
	fmt.Printf("%x\n", hash)
}

func createFile() {
	name := "mega"
	fmt.Printf("creating file: %s \n", name)
	data := make([]byte, 256)
	src := string("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n")
	copy(data, src)
	err := os.WriteFile(name, data, 0666)
	if err != nil {
		fmt.Printf("Failed to save file: %s \n", err)
	}
}

func generateRandomPasswords() {
	for range 8 {
		s, err := crutils.GenerateRandomPassword(18)
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

func tst() {
	fmt.Println("test success")
}
