package main

import (
	"bytes"
	"container/list"
	"fmt"
	"sort"
	"strconv"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var BarCol  = "   │—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————"
var BarNorm = "   │———————————————————————————————————————————————————————————————————————————————————————————————————"
var Bar = BarNorm
var defaultPrompt = "Enter text: "
const newline = byte('\n')

func changeFrameStyle() {
	if Bar == BarCol {
		Bar = BarNorm
	} else {
		Bar = BarCol
	}
}

func prepareTextContentForDisplay() {
	if !items[cur].prepared {
		crutils.Substitute(items[cur].src, '\r', newline)
		createLineList()
		items[cur].prepared = true
	}
}

func createLineList() {
	items[cur].console = list.New()
	s := items[cur].src
	beg := 0
	for i := 0; i < len(s); i++ {
		if s[i] == newline {
			items[cur].console.PushBack(s[beg:i])
			beg = i + 1
		}
	}
	if beg < len(s) {
		items[cur].console.PushBack(s[beg:])
	}
}

func cat() {
	prepareTextContentForDisplay()
	displayTextContent()
}

func displayTextContent() {
	fmt.Println(Bar)
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		fmt.Printf("%03d│ %s\n", i, x.Value.([]byte))
		i++
	}
	fmt.Println(Bar)
}

func grep(arg []string, cryptic bool, scramble bool) {
	var pattern []byte
	if cryptic {
		fmt.Print("Enter pattern for search: ")
		if scramble {
			pattern = terminal.SecureInputLinux()
		} else {
			pattern = terminal.PasswordModeInput()
		}
	} else if len(arg) > 1 {
		pattern = []byte(arg[1])
	} else {
		fmt.Print("Enter pattern for search: ")
		pattern = terminal.StandardInput()
	}

	if pattern == nil {
		return
	}

	i := 0
	found := false
	fmt.Println(Bar)
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		s, _ := x.Value.([]byte)
		j := bytes.LastIndex(s, pattern)
		if j >= 0 {
			found = true
			if cryptic {
				beg := j + len(pattern)
				fmt.Printf("%03d│ %s\n", i, s[beg:])
			} else  {
				fmt.Printf("%03d│ %s\n", i, s)
			}
		}
		i++
	}
	fmt.Println(Bar)
	if !found {
		fmt.Println(">>> not found <<<")
	}
}

func appendLine(cryptic bool) {
	var s []byte
	fmt.Println(defaultPrompt)
	if cryptic {
		s = terminal.SecureInput()
	} else {
		s = terminal.StandardInput()
	}

	if s != nil {
		items[cur].console.PushBack(s)
		items[cur].changed = true
		cat()
	}
}

func textLineInsertSpace(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing")
	} else {
		i, ok := a2i(arg[1], 0, items[cur].console.Len())
		if ok {
			if insertLine(i, []byte("")) {
				cat()
			}
		}
	}
}

func insertLine(ln int, s []byte) bool {
	if ln >= items[cur].console.Len() {
		fmt.Printf(">>> Error: index %d is greater than size %d \n", ln, items[cur].console.Len())
		return false
	}

	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			items[cur].console.InsertBefore(s, x)
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func textLineInsert(arg []string, cryptic bool) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing")
		return
	}

	i, ok := a2i(arg[1], 0, items[cur].console.Len())
	if !ok {
		return
	}

	var s []byte
	fmt.Println(defaultPrompt)
	if cryptic {
		s = terminal.SecureInput()
	} else {
		s = terminal.StandardInput()
	}

	if s != nil {
		if insertLine(i, s) {
			cat()
		}
	}
}

func textLinesDelete(arg []string) {
	indexes := parseAndSortInts(arg)
	if indexes != nil {
		crutils.ReverseInt(indexes)
		for _, x := range indexes {
			deleteSingleLine(x)
		}
		cat()
	}
}

func deleteSingleLine(ln int) {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			destroyData(x.Value.([]byte))
			items[cur].console.Remove(x)
			items[cur].changed = true
		}
		i++
	}
}

func linesPrint(arg []string) {
	prepareTextContentForDisplay()

	indexes := parseAndSortInts(arg)
	total := len(indexes)
	if total == 0 {
		fmt.Println("Nothing to print")
	}

	var ln, i int
	fmt.Println(Bar)
	for x := items[cur].console.Front(); x != nil && i < total; x = x.Next() {
		if indexes[i] == ln {
			fmt.Printf("%03d│ %s\n", ln, x.Value.([]byte))
			i++
		}
		ln++
	}
	fmt.Println(Bar)
}

func parseAndSortInts(arg []string) []int {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing")
		return nil
	}

	var indexes []int
	for _, s := range arg[1:] {
		num, ok := a2i(s, 0, items[cur].console.Len())
		if !ok {
			return nil
		}
		indexes = append(indexes, num)
	}

	sort.Ints(indexes)
	return indexes
}

func mergeLines(ln int) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			y := x.Next()
			if y == nil {
				fmt.Println(">>> Error: second line not found")
				return false
			}

			s1, _ := x.Value.([]byte)
			s2, _ := y.Value.([]byte)
			res := make([]byte, len(s1) + len(s2))
			copy(res, s1)
			copy(res[len(s1):], s2)
			items[cur].console.InsertBefore(res, x)
			destroyData(s1)
			destroyData(s2)
			items[cur].console.Remove(y)
			items[cur].console.Remove(x)
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func textLinesMerge(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing ")
		return
	}

	i, ok := a2i(arg[1], 0, items[cur].console.Len() - 1)
	if ok {
		if mergeLines(i) {
			cat()
		}
	}
}

func splitLine(arg []string) {
	if len(arg) < 3 {
		fmt.Printf(">>> Error: three params expected, got %d \n", len(arg))
		return
	}

	ln, ok := a2i(arg[1], 0, items[cur].console.Len())
	if ok {
		pos, ok := a2i(arg[2], 0, 100000)
		if ok {
			if split(ln, pos) {
				cat()
			}
		}
	}
}

func split(ln, pos int) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			s, _ := x.Value.([]byte)
			if pos >= len(s) {
				fmt.Printf(">>> Error: split position %d exceeds line length %d \n", pos, len(s))
				return false
			}

			items[cur].console.InsertAfter(s[pos:], x)
			s = s[:pos]
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func resizeLn(ln, pos int) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			s, _ := x.Value.([]byte)
			if pos >= len(s) {
				fmt.Printf(">>> Error: split position %d exceeds line length %d \n", pos, len(s))
				return false
			}

			destroyData(s[pos:])
			s = s[:pos]
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func resizeLine(arg []string) {
	// todo;
	if len(arg) < 3 {
		fmt.Printf(">>> Error: three params expected, got %d \n", len(arg))
		return
	}

	ln, ok := a2i(arg[1], 0, items[cur].console.Len())
	if ok {
		pos, ok := a2i(arg[2], 0, 100000)
		if ok {
			if resizeLn(ln, pos) {
				cat()
			}
		}
	}
}

func extendLine(arg []string, cryptic bool) {
	if len(arg) < 2 {
		fmt.Printf(">>> Error: three params expected, got %d \n", len(arg))
		return
	}

	ln, ok := a2i(arg[1], 0, items[cur].console.Len())
	if !ok {
		return
	}

	var s []byte
	fmt.Println(defaultPrompt)
	if cryptic {
		s = terminal.SecureInput()
	} else {
		s = terminal.StandardInput()
	}
	if s != nil {
		if extendLn(ln, s) {
			cat()
		}
	}
}

func extendLn(ln int, ext []byte) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			prev, _ := x.Value.([]byte)
			n := make([]byte, len(prev) + len(ext))
			copy(n, prev)
			copy(n[len(prev):], ext)
			items[cur].console.InsertAfter(n, x)
			destroyData(prev)
			items[cur].console.Remove(x)
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func a2i(s string, lowerBound int, upperBound int) (int, bool) {
	num, err := strconv.Atoi(s)
	if err != nil {
		fmt.Printf(">>> Error with param [%s]: %s \n", s, err)
		return 0, false
	} else if num < lowerBound {
		fmt.Printf(">>> Error: param [%s] is less than lower bound %d \n", s, lowerBound)
		return 0, false
	} else if num >= upperBound {
		fmt.Printf(">>> Error: param [%s] exceeds upper bound %d \n", s, upperBound)
		return 0, false
	}
	return num, true
}

func getCurrentConsoleSizeInBytes() (res int) {
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		s, _ := x.Value.([]byte)
		res += len(s) + 1 // implicit '\n' character at the end of line
	}
	return res
}

func content2raw() bool {
	total := getCurrentConsoleSizeInBytes()
	if total < 2 {
		fmt.Println(">>> Error: no content")
		return false
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

	destroyData(items[cur].dst)
	items[cur].dst = b[:total-1] // remove the last newline
	return true
}
