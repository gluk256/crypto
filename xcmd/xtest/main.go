package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/gluk256/crypto/terminal"
)

// do not delete this function, it might be useful for testing purposes
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

	switch os.Args[1][0] {
	case 'c':
		createFile()
	case 'i':
		fmt.Println(string(terminal.SecureInput(false)))
	case 'j':
		terminal.SecureInputTest()
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

func tst() {
	fmt.Println("test success")
}
