package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/crutils"
)

func generateHumanPasswords() {
	for x := 0; x < 8; x++ {
		s, err := crutils.GenerateRandomPassword(16)
		if err == nil {
			fmt.Println(string(s))
		} else {
			fmt.Printf("ERROR: %s\n", err)
			fmt.Println("Failed to generate the passwords")
			break
		}
	}
}

func generateBlob() {
	b := make([]byte, 512)
	err := crutils.StochasticRand(b)
	if err == nil {
		fmt.Printf("%x\n", b)
	} else {
		fmt.Printf("ERROR: %s\n", err)
	}
}

func main() {
	fmt.Println()
	if len(os.Args) > 1 {
		generateBlob()
	} else {
		generateHumanPasswords()
	}
	fmt.Println()
}
