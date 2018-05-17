package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gluk256/crypto/terminal"
)

func main() {
	var x []byte
	if len(os.Args) < 2 {
		test()
		return
	}

	arg := os.Args[1]
	a := arg[0]
	switch a {
	case 't':
		x = terminal.SecureInputTest()
		fmt.Println(string(x))
	case 'i':
		x = terminal.SecureInput()
		fmt.Println(string(x))
	case 'x':
		x = terminal.SecureInput()
		fmt.Println("will execute command ", string(x))
		cmd := exec.Command(string(x))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

func test() {

}
