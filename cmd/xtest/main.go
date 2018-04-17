package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/algo/keccak"
)

func main() {
	var x string
	if len(os.Args) < 2 {
		test()
		return
	}

	arg := os.Args[1]
	a := arg[0]
	switch a {
	case 't':
		x = terminal.SecureInputTest()
		fmt.Println(x)
	case 'i':
		x = terminal.SecureInput()
		fmt.Println(x)
	}
}

func test() {
	input := bufio.NewReader(os.Stdin)
	for {
		s, _ := input.ReadString('\n')
		s = strings.TrimRight(s, " \n\r")
		h := keccak.Digest([]byte(s), nil, 64)
		fmt.Printf("%x \n", h)
		if s == "q" {
			break
		}
	}
}
