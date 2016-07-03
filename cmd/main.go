package main

import (
	"fmt"
	"../SecureInput"
)

func main() {
	s := SecureInput.ReadFromTerminal()
	fmt.Println()
	fmt.Println(s)
}
