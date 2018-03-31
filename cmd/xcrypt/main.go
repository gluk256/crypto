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
	// todo: cleanup()
}

func run() {
	for {
		fmt.Print("> ")
		s, err := input.ReadString('\n')
		if err == nil {
			s = strings.TrimRight(s, " \n\r")
			if s == "q" {
				return
			} else {
				processCommand(s)
			}
		} else {
			fmt.Printf("Input Error: %s", err)
		}
	}
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}

	switch arg[0] {
	case "q":
		return
	////////////////////////////////////////////
	case "cat": // content display as text
		cat()
	case "cd": // content display as text
		cat()
	case "cc": // content load
		loadFile(arg)
	case "fl": // file load
		loadFile(arg)
	case "cl": // content load
		loadFile(arg)
	case "clb": // content load binary
		loadFile(arg)
	case "clt": // content load text
		if loadFile(arg) {
			cat()
		}
	case "ct": // content load text
		if loadFile(arg) {
			cat()
		}
	case "ft": // file load text
		if loadFile(arg) {
			cat()
		}
	case "fs": // file save
		saveFile(arg)
	case "cs": // content save
		saveFile(arg)
	case "fsp": // content save plain text // todo: rename to explicit "csplain"
		saveFilePlainText(arg)
	////////////////////////////////////////////
	case "grep":
		grep(arg, false)
	case "g":
		grep(arg, false)
	case "G":
		grep(arg, true)
	case "a": // editor line append
		appendLine(false)
	case "A": // editor line append cryptic
		appendLine(true)
	case "i": // editor line insert
		textLineInsert(arg, false)
	case "I": // editor line insert cryptic
		textLineInsert(arg, true)
	case "b": // editor insert line break (space)
		textLineInsertSpace(arg)
	case "d": // editor line delete
		textLinesDelete(arg)
	case "m": // editor lines merge
		textLinesMerge(arg)
	case "s": // editor line split
		splitLine(arg)
	case "e": // editor line extend (append to the end of line)
		extendLine(arg, false)
	case "E": // editor line extend cryptic (append to the end of line)
		extendLine(arg, true)
	case "p": // editor lines print
		linesPrint(arg)
	////////////////////////////////////////////
	default:
		fmt.Printf(">>> Wrong command: '%s' [%x] \n", cmd, []byte(cmd))
	}
}

func loadFile(arg []string) bool {
	if len(arg) < 2 {
		fmt.Println(">>> Error: filename is missing")
		return false
	}

	b, err := ioutil.ReadFile(arg[1])
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
		return false
	}

	items[cur].raw = b
	items[cur].prepared = false
	return true
}

func saveFile(arg []string) {
	if len(items[cur].raw) == 0 {
		fmt.Println(">>> Error: content is not found")
		return
	}

	var filename string
	var ok bool
	if len(arg) >= 2 {
		filename = arg[1]
	} else {
		filename, ok = prompt("Enter file name: ")
		if !ok {
			return
		}
	}

	err := ioutil.WriteFile(filename, items[cur].raw, 0777)
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
	}
}

func saveFilePlainText(arg []string) {
	s, ok := prompt("Do you really want to save plain text? ")
	if !ok {
		return
	}
	if s != "y" && s != "yes" {
		return
	}

	if content2raw() {
		saveFile(arg)
	}
}
