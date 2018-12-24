package main

import (
	"fmt"
	"os"
	"strings"
	"github.com/gluk256/crypto/crutils"
)

func main() {
	var hex bool
	if len(os.Args) > 1 {
		hex = strings.Contains(os.Args[1], "x")
	}

	fmt.Println()
	if hex {
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
