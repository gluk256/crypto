package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/crutils"
)

func main() {
	fmt.Println()
	if len(os.Args) > 1 {
		b := make([]byte, 512)
		err := crutils.StochasticRand(b)
		if err == nil {
			fmt.Printf("%x\n", b)
		} else {
			fmt.Printf("Error: %s\n", err)
		}
	} else {
		for x := 0; x < 8; x++ {
			s, err := crutils.GenerateRandomPassword(16)
			if err == nil {
				fmt.Println(string(s))
			} else {
				fmt.Printf("ATTENTION!!!\nERROR: %s\n", err)
				return
			}
		}
	}
}
