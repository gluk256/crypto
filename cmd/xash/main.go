package main

import (
	"fmt"
	"os"
	"github.com/gluk256/crypto/crutils"
)

func main() {
	var x string
	if len(os.Args) > 1 {
		//x = os.Args[1]
		fmt.Scanf("%s", &x)
		x = crutils.SHash(x)
	} else {
		x = crutils.XHash()
	}

	fmt.Println(x)
}

