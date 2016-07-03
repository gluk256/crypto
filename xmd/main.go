package main

import (
	"fmt"
	"github.com/gluk256/crypto/SecureInput"
)

func main() {
	s := SecureInput.ReadFromTerminal()
	fmt.Println()
	fmt.Println(s)
}
