package main

import (
	"bufio"
	"container/list"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
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
	quit = string("q")
)

var (
	witness keccak.Keccak512
	input   = bufio.NewReader(os.Stdin)
	items   [MaxItems]Content
	cur     int
	steg    int
)

func main() {
	initialize()

	if len(os.Args) > 1 {
		crutils.CollectEntropy()
		// todo: this should be interpreted as encrypt/decrypt file
		// flags: -e, -d, -x (encrypt with verify password)
		//filename := os.Args[1]
		//processCommand("decrypt " + filename)
	}

	for {
		crutils.CollectEntropy()
		s, ok := prompt("Enter command: ")
		cmd := string(s)
		if ok {
			if cmd == quit {
				if checkQuit() {
					break
				}
			} else {
				processCommand(cmd)
			}
		}
	}

	deleteAll()
	testify()
}

func initialize() {
	steg = -1
	for i := 0; i < MaxItems; i++ {
		items[i].console = list.New()
	}
}

func prompt(p string) ([]byte, bool) {
	fmt.Print(p)
	const n = byte('\n')
	txt, err := input.ReadBytes(n)
	if err != nil {
		fmt.Printf(">>> Input Error: %s \n", err)
		return []byte(""), false
	}
	last := len(txt) - 1
	if last >= 0 && txt[last] == n {
		txt = txt[:last]
	}
	crutils.CollectEntropy()
	return txt, true
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}

	switch arg[0] {
	case "frame":
		changeFrameStyle()
	case "reset":
		reset(arg)
	case "steg": // mark/unmark steganographic content
		markSteg()
	case "next":
		cur = (cur + 1) % 2
		cat()
	case "info":
		info()
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
		grep(arg, false, false)
	case "g":
		grep(arg, true, false)
	case "G":
		grep(arg, true, true)
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
	items[cur].changed = false
	return true
}

func saveFile(arg []string) {
	if len(items[cur].dst) == 0 {
		fmt.Println(">>> Error: content is not found")
		return
	}

	var filename string
	if len(arg) >= 2 {
		filename = arg[1]
	} else {
		f, ok := prompt("Enter file name: ")
		if ok {
			filename = string(f)
		} else {
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
	answer := string(s)
	if answer != "y" && answer != "yes" {
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
		answer := string(s)
		return (answer == "y" || answer == "yes")
	}
	return true
}

func destroyData(b []byte) {
	// overwrite; prevent compiler optimization
	sz := len(b)
	crutils.RandXor(b, sz)
	crutils.ReverseByte(b[sz/2:])
	witness.Write(b)
	keccak.XorInplace(b, b, sz)
	witness.Write(b)
}

func deleteContent(i int) {
	if items[i].console != nil {
		for x := items[i].console.Front(); x != nil; x = items[i].console.Front() {
			destroyData(x.Value.([]byte))
			items[i].console.Remove(x)
		}
	}

	destroyData(items[cur].src)
	destroyData(items[cur].dst)
}

func deleteAll() {
	for i := 0; i < MaxItems; i++ {
		deleteContent(i)
	}
}

func reset(arg []string) {
	if len(arg) > 1 && arg[1] == "all" {
		deleteAll()
	} else {
		deleteContent(cur)
	}
}

func testify() {
	b := make([]byte, 32)
	witness.Read(b, 32)
	fmt.Printf("Proof of data destruction: [%x]\n", b)
}

func info() {
	fmt.Printf("cur = %d, steg = %d \n", cur, steg)
}

func markSteg() {
	if steg < 0 {
		steg = cur
	} else {
		steg = -1
	}
	info()
}
