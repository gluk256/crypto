package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
)

func main() {
	if len(os.Args) > 1 {
		var x string
		fmt.Scanf("%s", &x) // todo: review
		s := terminal.SSha2(x)
		fmt.Println(s)
	} else {
		terminal.PrintHashedInput()
	}
}

