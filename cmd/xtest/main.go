package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gluk256/crypto/terminal"
)

func main() {
	if len(os.Args) < 2 {
		crypticExe()
		return
	}

	arg := os.Args[1]
	a := arg[0]
	switch a {
	case 't':
		tst()
	case 'i':
		text := terminal.SecureInput()
		fmt.Println(string(text))
	case 'x':
		crypticExe()
	}
}

func crypticExe() {
	x := terminal.SecureInput()
	cmd := exec.Command(string(x))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func tst() {

}
