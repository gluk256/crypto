package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"
	"io/ioutil"
	"container/list"
)

type Content struct {
	src      []byte
	dst      []byte
	console  *list.List
	prepared bool
	changed  bool
}

const (
	MaxItems = 2
)

var (
	input = bufio.NewReader(os.Stdin)
	items [MaxItems]Content
	cur int
	steg int
)

func main() {
	steg = 1
	// initEntropy() // collect comp-specific data
	if len(os.Args) > 1 {
		collectEntropy()
		// todo: this should be interpreted as decrypt cmd
		//filename := os.Args[1]
		//processCommand("decrypt " + filename)
	}

	for {
		collectEntropy()
		s, ok := prompt("Enter command: ")
		if ok {
			if s == "q" {
				if checkQuit() {
					break
				}
			} else {
				processCommand(s)
			}
		}
	}

	deleteAll()
	testify()
}

func prompt(p string) (string, bool) {
	fmt.Print(p)
	txt, err := input.ReadString('\n')
	if err != nil {
		fmt.Printf(">>> Input Error: %s \n", err)
		return "", false
	}
	txt = strings.TrimRight(txt, " \n\r")
	collectEntropy()
	return txt, true
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}

	switch arg[0] {
	case "frame": // second param: "col" or "norm"
		changeFrameStyle(arg[1])
	case "clear":
		deleteAll()
	////////////////////////////////////////////
	case "cat": // content display as text
		cat()
	case "cc": // content display as text
		cat()
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
	case "fsp": // content save plain text
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
	deleteContent(cur)

	if len(arg) < 2 {
		fmt.Println(">>> Error: filename is missing")
		return false
	}

	b, err := ioutil.ReadFile(arg[1])
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
		return false
	}

	items[cur].src = b
	items[cur].dst = nil
	items[cur].console = list.New()
	items[cur].prepared = false
	return true
}

func saveFile(arg []string) {
	if len(items[cur].dst) == 0 {
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

	err := ioutil.WriteFile(filename, items[cur].dst, 0777)
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
	} else {
		items[cur].changed = false
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

func checkQuit() bool {
	if items[cur].changed {
		s, ok := prompt("The file is not saved. Do you really want to quit and lose the changes? ")
		if !ok {
			return false
		}
		return (s == "y" || s == "yes")
	}
	return true
}

func collectEntropy() {
	// todo
}

func deleteContent(i int) {
	// todo
}

func deleteAll() {
	for i := 0; i < MaxItems; i++ {
		deleteContent(i)
	}
}

func testify() {
	// todo
}
