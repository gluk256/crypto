package main

import (
	"bytes"
	"container/list"
	"fmt"
	"sort"
	"strconv"

	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

func deriveConsoleFromSrc() {
	primitives.Substitute(items[cur].src, '\r', newline)
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
	if len(items[cur].src) != 0 && items[cur].console.Len() == 0 {
		deriveConsoleFromSrc()
	}
	displayContentAsText()
}

func displayContentAsText() {
	i := 0
	fmt.Println(Bar)
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
			pattern = terminal.SecureInputLinux(false)
		} else {
			pattern = terminal.PasswordModeInput()
		}
	} else if len(arg) > 1 {
		pattern = []byte(arg[1])
	} else {
		fmt.Print("Enter pattern for search: ")
		pattern = terminal.PlainTextInput()
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
			} else {
				fmt.Printf("%03d│ %s\n", i, s)
			}
		}
		i++
	}
	fmt.Println(Bar)
	if !found {
		fmt.Println(">>> not found <<<")
	}

	crutils.AnnihilateData(pattern)
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

func deleteLineAtIndex(ln int) {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			deleteLine(cur, x)
			return
		} else {
			i++
		}
	}
}

func parseAndSortIntArgs(arg []string) []int {
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
			res := make([]byte, len(s1)+len(s2))
			copy(res, s1)
			copy(res[len(s1):], s2)
			items[cur].console.InsertBefore(res, x)
			deleteLine(cur, y)
			deleteLine(cur, x)
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func splitLine(ln, pos int) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			s, _ := x.Value.([]byte)
			if pos >= len(s) {
				fmt.Printf(">>> Error: split position %d exceeds line length %d \n", pos, len(s))
				return false
			}

			items[cur].console.InsertAfter(s[pos:], x)
			items[cur].console.InsertAfter(s[:pos], x)
			items[cur].console.Remove(x)
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func cutLine(ln, pos int) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			s, _ := x.Value.([]byte)
			if pos >= len(s) {
				fmt.Printf(">>> Error: split position %d exceeds line length %d \n", pos, len(s))
				return false
			}

			crutils.AnnihilateData(s[pos:])
			s = s[:pos]
			items[cur].changed = true
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func extendLine(ln int, ext []byte) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			prev, _ := x.Value.([]byte)
			n := make([]byte, len(prev)+len(ext))
			copy(n, prev)
			copy(n[len(prev):], ext)
			items[cur].console.InsertAfter(n, x)
			deleteLine(cur, x)
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

func getConsoleSizeInBytes(i int) (res int) {
	for x := items[i].console.Front(); x != nil; x = x.Next() {
		s, _ := x.Value.([]byte)
		res += len(s) + 1 // implicit '\n' character at the end of line
	}
	return res
}
