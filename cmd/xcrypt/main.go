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

const MaxItems = 2

var (
	witness keccak.Keccak512
	items   [MaxItems]Content
	cur     int
	steg    int
)

func main() {
	initialize()

	if len(os.Args) > 1 {
		// todo: this should be interpreted as encrypt/decrypt file
		// flags: -e, -d, -x (encrypt with verify password)
		//filename := os.Args[1]
		//processCommand("decrypt " + filename)
	}

	for {
		fmt.Print("Enter command: ")
		s := terminal.StandardInput()
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
	testify()
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

	switch arg[0] {
	case "frame":
		ChangeFrameStyle()
	case "reset":
		Reset(arg)
	case "steg": // mark/unmark steganographic content
		MarkSteg()
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
	////////////////////////////////////////////
	case "ec":
		EncryptAndSaveContent(arg)
	case "ex":
		EncryptAndSaveSteg(arg)
	case "dc":
		DecryptContent(arg)
	case "dx":
		DecryptSteg(arg)
	case "ef": // load file, encrypt, and save (without cat)
		EncryptFile(arg)
	case "fe":
		EncryptFile(arg)
	case "df": // load file, decrypt, and save in plain form
		DecryptFile(arg)
	case "fd":
		DecryptFile(arg)
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
			annihilateData(b)
		}
	}
}

func FileSave(arg []string) {
	b := content2raw()
	encryptData(b)
	if b != nil {
		saveData(arg, b)
		annihilateData(b)
	}
}

func getFileName (arg []string) string {
	var filename string
	if len(arg) >= 2 {
		filename = arg[1]
	} else {
		fmt.Println("Enter file name: ")
		f := terminal.StandardInput()
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

func annihilateData(b []byte) {
	if len(b) != 0 {
		// overwrite; prevent compiler optimization
		sz := len(b)
		crutils.RandXor(b, sz)
		crutils.ReverseByte(b[sz / 2:])
		witness.Write(b)
		keccak.XorInplace(b, b, sz)
		witness.Write(b)
	}
}

func deleteLine(i int, e *list.Element) {
	annihilateData(e.Value.([]byte))
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
	// most of src must be already destroyed, byt still
	witness.Write(items[cur].src)
	annihilateData(items[cur].src)
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

func testify() {
	b := make([]byte, 32)
	witness.Read(b, 32)
	fmt.Printf("Proof of data destruction: [%x]\n", b)
}

func info() {
	fmt.Printf("cur = %d, steg = %d \n", cur, steg)
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
	s := terminal.StandardInput()
	if s == nil {
		return false
	}
	answer := string(s)
	return (answer == "y" || answer == "yes")
}

func encryptData(data []byte) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}

func EncryptAndSaveContent(args []string) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}

func EncryptAndSaveSteg(args []string) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}

func DecryptContent(args []string) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}

func DecryptSteg(args []string) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}

// load file, encrypt, and save (without cat)
func EncryptFile(args []string) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}

// load file, decrypt, and save in plain form
func DecryptFile(args []string) {
	// todo: implement!!!!!
	fmt.Println("NOT IMPLEMENTED")
}
