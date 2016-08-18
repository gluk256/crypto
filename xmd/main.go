package main

import (
	"fmt"
	"github.com/gluk256/crypto/SecureInput"
	"os"
)


func main() {
	var x string
	if len(os.Args) > 1 {
		x = os.Args[1]
		if '-' == x[0] {
			x = SecureInput.XHash()
		} else {
			x = SecureInput.SHash(x)
		}
	} else {
		x = SecureInput.ReadFromTerminal()
	}

	fmt.Println()
	fmt.Println(x)
}
