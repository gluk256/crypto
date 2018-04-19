package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"

	"github.com/gluk256/crypto/algo/keccak"
//	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func main() {
	var x []byte
	if len(os.Args) < 2 {
		test()
		return
	}

	arg := os.Args[1]
	a := arg[0]
	switch a {
	case 't':
		x = terminal.SecureInputTest()
		fmt.Println(string(x))
	case 'i':
		x = terminal.SecureInput()
		fmt.Println(string(x))
	}
}

func testHash() {
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

func test() {

}
