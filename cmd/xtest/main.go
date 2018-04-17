package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
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
	var h keccak.Keccak512
	input := bufio.NewReader(os.Stdin)
	for {
		s, _ := input.ReadString('\n')
		s = strings.TrimRight(s, " \n\r")
		crutils.UpdateEntropy(&h)
		if s == "q" {
			break
		}
	}

	//var t, t2 time.Time
	//j := t.UnixNano()
	//fmt.Printf("%x \n", j)
	//t = t.Add(time.Second)
	//fmt.Printf("%x \n", t.UnixNano())
	//d := t.Sub(t2)
	////z := t.Sub(t2).Nanoseconds()
	//fmt.Printf("%d \n", int64(d))
}
