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
	key      []byte
	pad      []byte
	console  *list.List
	prepared bool
	changed  bool
}

const (
	version  = 2
	MaxItems = 2
	steg     = 1
)

var (
	witness keccak.Keccak512
	items   [MaxItems]Content
	cur     int
	//steg    int
)

func main() {
	initialize()

	if len(os.Args) == 2 {
		fmt.Println("Not enough args. Usage:")
		fmt.Println("xcrypt [flags src_file_name]")
		return
	} else if len(os.Args) > 2 {
		if FileLoad(os.Args[1:], false) {
			contentDecrypt(os.Args[1:])
		}
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
	crutils.ProveDataDestruction()
}

func initialize() {
	crutils.CollectEntropy()
	for i := 0; i < MaxItems; i++ {
		items[i].console = list.New()
	}
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}
	//cryptic, verifyPass, show := parseFlags(arg[1]) //todo: delete

	switch arg[0] {
	case "frame":
		ChangeFrameStyle()
		cat()
	case "reset":
		Reset(arg)
	case "switch":
		cur = (cur + 1) % 2
		cat()
	case "sw":
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
	case "cds": // content decrypt steg
		stegDecrypt(arg)
	case "csd": // content decrypt steg
		stegDecrypt(arg)
	case "cdd": // content decrypt steg
		stegDecrypt(arg)
	case "cd": // content decrypt
		contentDecrypt(arg)
	////////////////////////////////////////////
	case "dd": // file decrypt
		if FileLoad(arg, false) {
			contentDecrypt(arg)
		}
	case "fd": // file decrypt
		if FileLoad(arg, false) {
			contentDecrypt(arg)
		}
	case "fl": // file load
		FileLoad(arg, false)
	case "fo": // file load text
		FileLoad(arg, true)
	case "flt": // file load text
		FileLoad(arg, true)
	case "fs": // encrypt file and save
		FileSave(arg)
	case "fsplain": // file save plain text
		FileSavePlainText(arg)
	case "fss": // steganographic save
		FileSaveSteg(arg)
	case "ss": // steganographic save
		FileSaveSteg(arg)
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

func FileLoad(arg []string, show bool) bool {
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
	if show {
		cat()
	}

	return true
}

func saveData(arg []string, data []byte) {
	if len(data) == 0 {
		fmt.Println(">>> Error: content is not found")
		return
	}

	filename := getFileName(arg)
	if len(filename) == 0 {
		fmt.Println(">>> Error: filename is empty")
		return
	}

	err := ioutil.WriteFile(filename, data, 0666)
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
	} else {
		items[cur].changed = false
	}
}

func FileSavePlainText(arg []string) {
	if confirm("Do you really want to save plain text?") {
		b := content2raw(cur, 0)
		if b != nil {
			saveData(arg, b)
			crutils.AnnihilateData(b)
		}
	}
}

func FileSave(arg []string) {
	b := content2raw(cur, 0)
	x := encryptData(arg, b)
	if b != nil {
		saveData(arg, x)
		crutils.AnnihilateData(x)
		crutils.AnnihilateData(b)
	}
}

func getFileName(arg []string) string {
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

func content2raw(index int, capacity int) []byte {
	total := getConsoleSizeInBytes(index)
	if total < 2 {
		fmt.Println(">>> Error: no content")
		return nil
	}

	if total > capacity {
		capacity = total
	}

	i := 0
	b := make([]byte, total, capacity)

	for x := items[index].console.Front(); x != nil; x = x.Next() {
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
	crutils.AnnihilateData(items[cur].key)

	items[cur].src = nil
	items[cur].key = nil
	items[cur].pad = nil
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
	fmt.Printf("len(0) = %d, len(1) = %d, \n", len(items[0].src), len(items[1].src))
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

func getPassword(cryptic bool, checkExisting bool) []byte {
	if len(items[cur].key) > 0 && checkExisting {
		if confirm("Do you want to use existing key? ") {
			return items[cur].key
		}
	}

	var res []byte
	//if randpass {
	//	res = crutils.RandPass(16)
	//	fmt.Println(string(res))
	//} else
	if cryptic {
		res = terminal.SecureInput(false)
	} else {
		fmt.Print("please enter the password: ")
		res = terminal.PasswordModeInput()
	}
	if len(res) < 3 {
		res = nil
	} else {
		items[cur].key = res
	}
	return res
}

func FileSaveSteg(arg []string) {
	if steg < 0 || items[steg].console.Len() == 0 {
		fmt.Println(">>> Error: steganographic content does not exist")
		return
	}

	plain := (steg + 1) % 2
	const requiredDiff = crutils.AesEncryptedSizeDiff + crutils.SaltSize
	plainContent := content2raw(plain, 0)
	stegContent := content2raw(steg, len(plainContent))
	defer crutils.AnnihilateData(plainContent)
	defer crutils.AnnihilateData(stegContent)

	diff := len(plainContent) - len(stegContent)
	if diff < requiredDiff {
		fmt.Printf(">>> Error: plain text is too small in comparison with steganographic content [%d vs. %d] \n",
			len(plainContent), len(stegContent))
		return
	} else if diff > requiredDiff {
		padSize := diff - requiredDiff
		pad := make([]byte, padSize)
		stegContent = append(stegContent, pad...)
	}

	var insecure bool
	if len(arg) > 1 {
		insecure = strings.Contains(arg[1], "i")
	}
	fmt.Println("password for steganographic content encryption")
	keySteg := getPassword(!insecure, true)
	if len(keySteg) == 0 {
		fmt.Println(">>> Error: wrong key")
		return
	}

	fmt.Println("password for plain text encryption")
	keyPlain := getPassword(!insecure, true)
	if len(keyPlain) == 0 {
		crutils.AnnihilateData(keySteg)
		fmt.Println(">>> Error: wrong key")
		return
	}

	encryptedSteg, err := crutils.Encrypt(keySteg, stegContent)
	if err != nil {
		fmt.Printf(">>> Error encrypting steg: %s\n", err)
		return
	}
	res, err := crutils.EncryptSteg(keyPlain, plainContent, encryptedSteg)
	if err != nil {
		fmt.Printf(">>> Error encrypting cur: %s\n", err)
		return
	}

	if res != nil {
		saveData(arg, res)
		crutils.AnnihilateData(res)
	}
}

func encryptData(args []string, d []byte) []byte {
	var secure bool
	if len(args) > 1 {
		secure = strings.Contains(args[1], "s")
	}
	key := getPassword(secure, true)
	if len(key) == 0 {
		fmt.Println(">>> Error: wrong key")
		return nil
	}
	res, err := crutils.Encrypt(key, d)
	if err != nil {
		fmt.Printf(">>> Error: %s\n", err)
		return nil
	}
	return res
}

func contentDecrypt(arg []string) bool {
	var secure, hide bool
	if len(arg) > 1 {
		secure = strings.Contains(arg[1], "s")
		hide = strings.Contains(arg[1], "h")
	}

	content := make([]byte, len(items[cur].src))
	copy(content, items[cur].src)

	key := getPassword(secure, true)
	if len(key) == 0 {
		fmt.Println(">>> Error: wrong key")
		return false
	}

	b, s, err := crutils.Decrypt(key, content)
	if err != nil {
		fmt.Printf(">>> Error: %s\n", err)
		return false
	}

	items[cur].src = b
	items[cur].pad = s
	if !hide {
		cat()
	}
	return true
}

func stegDecrypt(arg []string) bool {
	var insecure, hide bool
	if len(arg) > 1 {
		insecure = strings.Contains(arg[1], "i")
		hide = strings.Contains(arg[1], "h")
	}

	stegContent := make([]byte, len(items[cur].pad))
	copy(stegContent, items[cur].pad)

	key := getPassword(!insecure, false)
	if len(key) == 0 {
		fmt.Println(">>> Error: wrong key")
		return false
	}

	b, _, err := crutils.DecryptStegContentOfUnknownSize(key, stegContent)
	if err != nil {
		fmt.Printf(">>> Error: %s\n", err)
		return false
	}

	items[steg].src = b
	items[steg].key = key
	if !hide {
		cat()
	}
	return true
}
