package main

import (
	"fmt"
	"strings"
	"container/list"
	"strconv"
	"sort"

	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var BarCol = "   │—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————"
var BarNorm = "   │———————————————————————————————————————————————————————————————————————————————————————————————————"
var Bar = BarNorm
var defaultPrompt = "Enter text: "

func prepareContentForDisplay() {
	if !items[cur].prepared {
		s := string(items[cur].raw)
		if strings.Count(s, "\r") > 0 {
			s = strings.Replace(s, "\n\r", "\n", -1)
			s = strings.Replace(s, "\r\n", "\n", -1)
			s = strings.Replace(s, "\r", "\n", -1)
		}

		arr := strings.Split(s, "\n")
		items[cur].console = list.New()
		for _, x := range arr {
			items[cur].console.PushBack(x)
		}

		items[cur].prepared = true
	}
}

func cat() {
	prepareContentForDisplay()
	displayContent()
}

func displayContent() {
	fmt.Println(Bar)
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		fmt.Printf("%03d│ %s\n", i, x.Value)
		i++
	}
	fmt.Println(Bar)
}

func grep(arg []string, cryptic bool) {
	var ok bool
	var pattern string
	if cryptic {
		pattern = terminal.SecureInputLinux()
	} else if len(arg) > 1 {
		pattern = arg[1]
	} else {
		pattern, ok = prompt("Enter pattern for search: ")
		if !ok {
			return
		}
	}

	found := false
	i := 0
	fmt.Println(Bar)
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		s, _ := x.Value.(string)
		if strings.Contains(s, pattern) {
			fmt.Printf("%03d│ %s\n", i, x.Value)
			found = true
		}
		i++
	}
	fmt.Println(Bar)
	if !found {
		fmt.Println(">>> not found <<<")
	}
}

func appendLine(cryptic bool) {
	var ok bool
	var s string
	if cryptic {
		s = terminal.SecureInput()
	} else {
		s, ok = prompt(defaultPrompt)
		if !ok {
			return
		}
	}

	items[cur].console.PushBack(s)
	items[cur].changed = true
	cat()
}

func insertLine(ln int, s string) bool {
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

func textLineInsertSpace(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing")
	} else {
		i, ok := a2i(arg[1], 0, items[cur].console.Len())
		if ok {
			if insertLine(i, "") {
				cat()
			}
		}
	}
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

	var s string
	if cryptic {
		s = terminal.SecureInput()
	} else {
		s, ok = prompt(defaultPrompt)
		if !ok {
			return
		}
	}

	if insertLine(i, s) {
		cat()
	}
}

func textLinesDelete(arg []string) {
	indexes := parseAndSortInts(arg)
	if indexes != nil {
		crutils.Reverse(indexes)
		for _, x := range indexes {
			deleteSingleLine(x)
		}
		cat()
	}
}

func linesPrint(arg []string) {
	prepareContentForDisplay()

	indexes := parseAndSortInts(arg)
	sz := len(indexes)
	if sz == 0 {
		fmt.Println("Nothing to print")
	}

	var ln, i int
	fmt.Println(Bar)
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if indexes[i] == ln {
			fmt.Printf("%03d│ %s\n", ln, x.Value)
			i++
			if sz == i {
				break
			}
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

func deleteSingleLine(ln int) {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			items[cur].console.Remove(x)
			items[cur].changed = true
		}
		i++
	}
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

			s1, _ := x.Value.(string)
			s2, _ := y.Value.(string)
			items[cur].console.InsertBefore(s1+s2, x)
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
			s, _ := x.Value.(string)
			if pos >= len(s) {
				fmt.Printf(">>> Error: split position %d exceeds line length %d \n", pos, len(s))
				return false
			}

			items[cur].console.InsertBefore(s[:pos], x)
			items[cur].console.InsertBefore(s[pos:], x)
			items[cur].console.Remove(x)
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
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

	var s string
	if cryptic {
		s = terminal.SecureInput()
	} else {
		s, ok = prompt(defaultPrompt)
		if !ok {
			return
		}
	}

	if extendLn(ln, s) {
		cat()
	}
}

func extendLn(ln int, s string) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			old, _ := x.Value.(string)
			items[cur].console.InsertAfter(old+s, x)
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

func content2raw() bool {
	var res string
	last := items[cur].console.Len() - 1
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		s, _ := x.Value.(string)
		if i != last {
			res += s + "\n"
		} else {
			res += s
		}
		i++
	}

	if len(res) == 0 {
		fmt.Println(">>> Error: nothing to save")
		return false
	}

	items[cur].raw = []byte(res)
	return true
}
