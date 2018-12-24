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
		crutils.StochasticRand(b)
		fmt.Printf("%x\n", b)
	} else {
		for x := 0; x < 8; x++ {
			s := crutils.RandPass(16)
			fmt.Println(string(s))
		}
	}
}
