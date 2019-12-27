package main

import (
	"container/list"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
	"github.com/gluk256/crypto/xcmd/common"
)

const (
	NumItems = 2
	steg     = 1
	face     = 0
)

type Content struct {
	src      []byte
	key      []byte
	pad      []byte
	console  *list.List
	prepared bool
	changed  bool
}

var (
	items [NumItems]Content
	cur   int
)

func initialize() {
	for i := 0; i < NumItems; i++ {
		items[i].console = list.New()
	}
}

func cleanup() {
	deleteAll()
	crutils.ProveDataDestruction()
}

func deleteAll() {
	for i := 0; i < NumItems; i++ {
		deleteContent(i)
	}
}

func deleteLine(i int, e *list.Element) {
	crutils.AnnihilateData(e.Value.([]byte))
	items[i].console.Remove(e)
}

func deleteContent(i int) {
	crutils.AnnihilateData(items[cur].key)
	crutils.AnnihilateData(items[cur].src)
	crutils.AnnihilateData(items[cur].pad)

	if items[i].console != nil {
		for x := items[i].console.Front(); x != nil; x = items[i].console.Front() {
			deleteLine(i, x)
		}
	}

	items[cur].src = nil
	items[cur].key = nil
	items[cur].pad = nil
}

func checkQuit() bool {
	if items[cur].changed {
		return confirm("The file is not saved. Do you really want to quit and lose the changes?")
	}
	return true
}

func reset(all bool) {
	if all {
		deleteAll()
	} else {
		deleteContent(cur)
	}
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

func getKey(cryptic bool, checkExisting bool) (res []byte) {
	if len(items[cur].key) > 0 {
		if checkExisting {
			if confirm("Do you want to use existing key? ") {
				return items[cur].key
			}
		}
	}

	if cryptic {
		res = common.GetPassword("s")
	} else {
		res = common.GetPassword("p")
	}

	crutils.AnnihilateData(items[cur].key)
	items[cur].key = res
	return res
}

func getFileName(arg []string) (res string) {
	if len(arg) >= 2 {
		res = arg[1]
	} else {
		fmt.Println("Enter file name: ")
		f := terminal.PlainTextInput()
		if f == nil {
			return ""
		} else {
			res = string(f)
		}
	}
	return res
}

func content2raw(index int, capacity int) []byte {
	total := getConsoleSizeInBytes(index)
	if total < 2 {
		fmt.Println(">>> Error: no content")
		return nil
	}

	if total > capacity {
		capacity = total * 2
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

func main() {
	if len(os.Args) == 2 {
		if !strings.Contains(os.Args[1], "h") {
			fmt.Println("ERROR: not enough args")
		}
		help()
		return
	}

	initialize()
	defer cleanup()

	if len(os.Args) > 2 {
		if FileLoad(os.Args[1:], false) {
			contentDecrypt(os.Args[1:])
		}
	}

	run()
}

func run() {
	for {
		fmt.Print("Enter command: ")
		s := terminal.PlainTextInput()
		if s != nil {
			cmd := string(s)
			if cmd == "q" {
				if checkQuit() {
					return
				}
			} else {
				processCommand(cmd)
			}
		}
	}
}

func FileLoad(arg []string, show bool) bool {
	deleteContent(cur)

	filename := getFileName(arg)
	if len(filename) == 0 {
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

// func FileSavePlainText(arg []string) {
// 	if confirm("Do you really want to save plain text?") {
// 		b := content2raw(cur, 0)
// 		if b != nil {
// 			saveData(arg, b)
// 			crutils.AnnihilateData(b)
// 		}
// 	}
// }

func FileSave(arg []string) {
	b := content2raw(cur, 0)
	x := encryptData(arg, b)
	if b != nil {
		saveData(arg, x)
		crutils.AnnihilateData(x)
		crutils.AnnihilateData(b)
	}
}

func FileSaveSteg(arg []string) {
	if steg < 0 || items[steg].console.Len() == 0 {
		fmt.Println(">>> Error: steganographic content does not exist")
		return
	}

	plainContent := content2raw(face, 0)
	stegContent := content2raw(steg, len(plainContent)*4)
	defer crutils.AnnihilateData(plainContent)
	defer crutils.AnnihilateData(stegContent)
	secure := (len(arg) < 2) || !strings.Contains(arg[1], "i")
	encrypedStegSize := len(stegContent) + crutils.EncryptedSizeDiff
	allowedStegSize := primitives.FindNextPowerOfTwo(len(stegContent))
	if encrypedStegSize > allowedStegSize {
		fmt.Printf(">>> Error: plain text is too small in comparison with steganographic content ")
		fmt.Printf("[%d vs. %d] \n", len(plainContent), len(stegContent))
		return
	}

	fmt.Println("password for steganographic content encryption")
	keySteg := getKey(secure, true)
	if len(keySteg) == 0 {
		fmt.Println(">>> Error: wrong key")
		return
	}

	fmt.Println("password for plain text encryption")
	keyPlain := getKey(secure, true)
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
	key := getKey(secure, true)
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
	var secure, mute bool
	if len(arg) > 1 {
		secure = strings.Contains(arg[1], "s")
		mute = strings.Contains(arg[1], "m")
	}

	content := make([]byte, len(items[cur].src))
	copy(content, items[cur].src)

	key := getKey(secure, true)
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
	if !mute {
		cat()
	}
	return true
}

func stegDecrypt(arg []string) bool {
	var secure, mute bool
	if len(arg) > 1 {
		secure = !strings.Contains(arg[1], "p")
		mute = strings.Contains(arg[1], "m")
	}

	stegContent := make([]byte, len(items[cur].pad))
	copy(stegContent, items[cur].pad)

	key := getKey(secure, false)
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
	cur = (cur + 1) % 2
	if !mute {
		cat()
	}
	return true
}
