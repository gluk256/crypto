package main

import (
	"container/list"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

type Content struct {
	src      []byte
	console  *list.List
	prepared bool
	changed  bool
}

const (
	MaxItems = 2
	version = 1
)

var (
	witness keccak.Keccak512
	items   [MaxItems]Content
	cur     int
	steg    int
)

func main() {
	initialize()

	if len(os.Args) > 3 {
		// todo: this should be interpreted as encrypt/decrypt file
		//cryptic, verifyPass, show := parseEncryptionFlag(os.Args[1:])
		//srcFilename := os.Args[1]
		//dstFilename := os.Args[2]
		//os.Args[3]: -e or -d
		//process command
		//return
	} else if len(os.Args) > 1 {
		fmt.Print("Not enough args")
		return
	}

	for {
		fmt.Print("Enter command: ")
		s := terminal.PlainTextInput()
		if s != nil {
			cmd := string(s)
			if cmd == "q" {
				if checkQuit() {
					break
				}
			} else {
				processCommand(cmd)
			}
		}
	}

	deleteAll()
	crutils.ProveDestruction()
}

func initialize() {
	crutils.CollectEntropy()
	steg = -1
	for i := 0; i < MaxItems; i++ {
		items[i].console = list.New()
	}
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}
	cryptic, verifyPass, show := parseEncryptionFlag(arg[1:])

	switch arg[0] {
	case "frame":
		ChangeFrameStyle()
		cat()
	case "reset":
		Reset(arg)
	case "steg": // mark/unmark steganographic content
		MarkSteg()
	case "next":
		cur = (cur + 1) % 2
		cat()
	case "info":
		info()
	case "ls":
		ls()
	////////////////////////////////////////////
	case "cat": // content display as text
		cat()
	case "cc": // content display as text
		cat()
	////////////////////////////////////////////
	case "fl": // file load
		FileLoad(arg)
	case "fo": // file load text
		if FileLoad(arg) {
			cat()
		}
	case "flt": // file load text
		if FileLoad(arg) {
			cat()
		}
	case "fs": // file save
		FileSave(arg)
	case "fsplain": // file save plain text
		FileSavePlainText(arg)
	////////////////////////////////////////////
	case "grep":
		grep(arg, false, false)
	case "g":
		grep(arg, true, false)
	case "G":
		grep(arg, true, true)
	case "a": // editor: append line to the end
		LineAppend(false)
	case "A": // editor: append line with cryptic input
		LineAppend(true)
	case "i": // editor: insert line at certain index
		LineInsert(arg, false)
	case "I": // editor: insert line cryptic
		LineInsert(arg, true)
	case "b": // editor: insert empty line (space)
		LineInsertSpace(arg)
	case "d": // editor: delete lines
		LinesDelete(arg)
	case "m": // editor: merge lines
		LinesMerge(arg)
	case "s": // editor: split lines
		LineSplit(arg)
	case "e": // editor: extend line (append to the end of line)
		LineExtend(arg, false)
	case "E": // editor: extend line cryptic
		LineExtend(arg, true)
	case "p": // editor: print lines
		LinesPrint(arg)
	case "c": // editor: cut line (delete from the end)
		LineCut(arg)
	////////////////////////////////////////////
	case "ei":
		EncryptInputAndPrintHex(cryptic, verifyPass)
	case "di":
		DecryptHexInput(cryptic, show)
	// todo: add other encrypt/decrypt commands from the bottom of this file
	////////////////////////////////////////////
	default:
		fmt.Printf(">>> Wrong command: '%s' [%x] \n", cmd, []byte(cmd))
	}
}

func FileLoad(arg []string) bool {
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
	items[cur].console = list.New()
	items[cur].prepared = false
	items[cur].changed = false
	return true
}

func saveData(arg []string, data []byte) {
	if len(data) == 0 {
		fmt.Println(">>> Error: content is not found")
		return
	}

	filename := getFileName(arg)
	if len(filename) == 0 {
		fmt.Println(">>> Error: filename is emprty")
		return
	}

	err := ioutil.WriteFile(filename, data, 0777)
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
	} else {
		items[cur].changed = false
	}
}

func FileSavePlainText(arg []string) {
	if confirm("Do you really want to save plain text?") {
		b := content2raw()
		if b != nil {
			saveData(arg, b)
			crutils.AnnihilateData(b)
		}
	}
}

func FileSave(arg []string) {
	b := content2raw()
	x := encryptData(b)
	if b != nil {
		saveData(arg, x)
		crutils.AnnihilateData(x)
		crutils.AnnihilateData(b)
	}
}

func getFileName (arg []string) string {
	var filename string
	if len(arg) >= 2 {
		filename = arg[1]
	} else {
		fmt.Println("Enter file name: ")
		f := terminal.PlainTextInput()
		if f == nil {
			return ""
		} else {
			filename = string(f)
		}
	}
	return filename
}

func content2raw() []byte {
	total := getConsoleSizeInBytes(cur)
	if total < 2 {
		fmt.Println(">>> Error: no content")
		return nil
	}

	i := 0
	b := make([]byte, total)
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		s, _ := x.Value.([]byte)
		copy(b[i:], s)
		i += len(s)
		b[i] = newline
		i++
	}

	return b[:total-1] // remove the last newline
}

func checkQuit() bool {
	if items[cur].changed {
		return confirm("The file is not saved. Do you really want to quit and lose the changes?")
	}
	return true
}

func deleteLine(i int, e *list.Element) {
	crutils.AnnihilateData(e.Value.([]byte))
	items[i].console.Remove(e)
}

func deleteContent(i int) {
	// console must be deleted first
	if items[i].console != nil {
		for x := items[i].console.Front(); x != nil; x = items[i].console.Front() {
			deleteLine(i, x)
		}
	}

	// first, feed to witness to prevent compiler optimization
	// most of src must be already destroyed
	witness.Write(items[cur].src)
	crutils.AnnihilateData(items[cur].src)
}

func deleteAll() {
	for i := 0; i < MaxItems; i++ {
		deleteContent(i)
	}
}

func Reset(arg []string) {
	if len(arg) > 1 && arg[1] == "all" {
		deleteAll()
	} else {
		deleteContent(cur)
	}
}

func info() {
	fmt.Printf("ver = %d, cur = %d, steg = %d \n", version, cur, steg)
}

func MarkSteg() {
	if steg < 0 {
		steg = cur
	} else {
		steg = -1
	}
	info()
}

func confirm(question string) bool {
	fmt.Printf("%s ", question)
	s := terminal.PlainTextInput()
	if s == nil {
		return false
	}
	answer := string(s)
	return (answer == "y" || answer == "yes")
}

func ls() {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		fmt.Printf(">>> Error: %s\n", err)
	}
	for _, f := range files {
		fmt.Printf("[%s] ", f.Name())
	}
	fmt.Println()
}
/////////////////////////////////////////////////////////////////////////

func parseEncryptionFlag(arg []string) (cryptic, verifyPass, show bool) {
	for _, a := range arg {
		if a == "-c" {
			cryptic = true
		} else if a == "-v" {
			verifyPass = true
		} else if a == "-p" {
			show = true
		}
	}
	return
}

func encryptData(data []byte) []byte {
	panic("NOT IMPLEMENTED")
	return nil
}

func EncryptContentAndSave(args []string, cryptic bool, verifyPass bool) {
	panic("NOT IMPLEMENTED")
}

func EncryptStegAndSave(args []string, cryptic bool, verifyPass bool) {
	panic("NOT IMPLEMENTED")
}

func EncryptFileAndSave(args []string, cryptic bool, verifyPass bool) {
	panic("NOT IMPLEMENTED")
}

func EncryptInputAndPrintHex(cryptic bool, verifyPass bool) {
	panic("NOT IMPLEMENTED")
}

func DecryptContent(args []string, cryptic bool, show bool) {
	panic("NOT IMPLEMENTED")
}

func DecryptFile(args []string, cryptic bool, show bool) {
	panic("NOT IMPLEMENTED")
}

func DecryptFileAndSave(args []string, cryptic bool) {
	panic("NOT IMPLEMENTED")
}

func DecryptFileSteg(args []string, firstLayerCryptic bool, show bool) {
	panic("NOT IMPLEMENTED")
}

func DecryptHexInput(cryptic bool, show bool) {
	panic("NOT IMPLEMENTED")
}
