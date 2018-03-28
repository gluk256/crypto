package main

import (
	"fmt"
	"os"
	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/crutils"
)


func main() {
	var x string
	if len(os.Args) <= 1 {
		crutils.Misctest()
		fmt.Println("test passed")
		return
	}

	arg := os.Args[1]
	a := arg[0]
	switch a {
	case 't':
		x = terminal.SecureInputTest()
		fmt.Println(x)
	case 'i':
		x = terminal.SecureInput()
		fmt.Println(x)
	case 'm':
		crutils.Misctest()
	}
}
