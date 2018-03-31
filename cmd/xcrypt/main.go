package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"
	"io/ioutil"
	"container/list"

	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/crutils"
)

type Content struct {
	raw []byte
	console *list.List
	prepared bool
}

const (
	MaxItems = 4
	Steg = 1
)

var (
	input = bufio.NewReader(os.Stdin)
	items [MaxItems]Content
	cur int
)

func main() {
	if len(os.Args) > 1 {
		arg := os.Args[1]
		a := arg[0]
		switch a {
		case 't':
			x := terminal.SecureInputTest()
			fmt.Println(x)
		case 'i':
			x := terminal.SecureInput()
			fmt.Println(x)
		case 'm':
			crutils.Misctest()
		}
	}

	run()
}

func run() {
	for {
		fmt.Print("> ")
		s, err := input.ReadString('\n')
		if err != nil {
			fmt.Printf("Input Error: %s", err)
			continue
		}
		s = strings.TrimRight(s, " \n\r")
		if s == "q" {
			// todo: 	cleanup()
			return
		} else {
			processCommand(s)
		}
	}
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}

	switch arg[0] {
	////////////////////////////////////////////
	case "cat": // content display as text
		cat()
	case "cd": // content display as text
		cat()
	case "cl": // content load
		loadContent(arg)
	case "clb": // content load binary
		loadContent(arg)
	case "clt": // content load text
		loadContent(arg)
		cat()
	//case "cs": // content save
	//	saveEncrypted(arg)
	//case "csp": // content save plain text // todo: rename to explicit "csplain"
	//	savePlain(arg)
	////////////////////////////////////////////
	case "a": // editor line append
		appendLine()
	case "i": // editor line insert
		textLineInsert(arg, false)
	case "b": // editor line break (insert space)
		textLineInsert(arg, true)
	case "d": // editor line delete
		textLineDelete(arg)
	case "m": // editor lines merge
		textLinesMerge(arg)
	case "s": // editor line split
		splitLine(arg)
	case "e": // editor line extend (append to the end of line)
		extendLine(arg)
	////////////////////////////////////////////
	default:
		fmt.Printf(">>> Wrong command: '%s' [%x] \n", cmd, []byte(cmd))
	}
}

func loadContent(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: filename is missing")
		return
	}

	b, err := ioutil.ReadFile(arg[1])
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
		return
	}

	items[cur].raw = b
}
