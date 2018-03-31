package main

import (
	"fmt"
	"strings"
	"container/list"
	"strconv"
	"sort"
)

func prompt() (string, bool) { // todo: rename
	//if len(info) > 0 {
	//	fmt.Print(info, ": ")
	//}
	fmt.Print("Enter text: ")
	txt, err := input.ReadString('\n')
	if err != nil {
		fmt.Printf(">>> Error: %s \n", err)
		return "", false
	}
	txt = strings.TrimRight(txt, " \n\r")
	return txt, true
}

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
	delimiter := "   │—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————+—————————"
	fmt.Println(delimiter)
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		fmt.Printf("%03d│ %s\n", i, x.Value)
		i++
	}
	fmt.Println(delimiter)
}

func appendLine() {
	s, ok := prompt()
	if ok {
		items[cur].console.PushBack(s)
		cat()
	}
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
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func textLineInsert(arg []string, delimiter bool) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing \n")
		return
	}

	i, ok := a2i(arg[1], 0, 1000000)
	if !ok {
		return
	}

	s := ""
	if !delimiter {
		s, ok = prompt()
		if !ok {
			return
		}
	}

	if insertLine(i, s) {
		cat()
	}
}

func textLineDelete(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing \n")
		return
	}

	var indexes []int
	for _, s := range arg[1:] {
		num, ok := a2i(s, 0, items[cur].console.Len())
		if !ok {
			return
		}
		indexes = append(indexes, num)
	}

	sort.Ints(indexes)
	reverse(indexes)

	for _, x := range indexes {
		deleteSingleLine(x)
	}

	cat()
}

func reverse(a []int) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
	}
}

func deleteSingleLine(ln int) {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			items[cur].console.Remove(x)
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
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func textLinesMerge(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing \n")
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
			return true
		}
		i++
	}

	fmt.Println(">>> Error: line not found")
	return false
}

func extendLine(arg []string) {
	if len(arg) < 2 {
		fmt.Printf(">>> Error: three params expected, got %d \n", len(arg))
		return
	}

	ln, ok := a2i(arg[1], 0, items[cur].console.Len())
	if ok {
		s, ok := prompt()
		if ok {
			if extendLn(ln, s) {
				cat()
			}
		}
	}
}

func extendLn(ln int, s string) bool {
	i := 0
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if i == ln {
			old, _ := x.Value.(string)
			items[cur].console.InsertAfter(old+s, x)
			items[cur].console.Remove(x)
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