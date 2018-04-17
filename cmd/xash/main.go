package main

import (
	"fmt"
	"os"

	"github.com/gluk256/crypto/terminal"
)

func main() {
	var x string
	if len(os.Args) > 1 {
		//x = os.Args[1]
		fmt.Scanf("%s", &x)
		x = terminal.SSha2(x)
	} else {
		x = terminal.XSha2()
	}

	fmt.Println(x)
}

