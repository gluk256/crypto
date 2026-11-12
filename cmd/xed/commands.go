package main

import (
	"fmt"

	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

var BarCol = "   │ ————~~————+————~~————+————~~————+————~~————+————~~————+————~~————+————~~————+————~~————+————~~————+"
var BarNorm = "   │ ———————————————————————————————————————————————————————————————————————————————————————————————————"
var Bar = BarNorm
var defaultPrompt = "Enter text: "

const newline = byte('\n')

func ChangeFrameStyle() {
	if Bar == BarCol {
		Bar = BarNorm
	} else {
		Bar = BarCol
	}
}

func LineAppendEmptyLine() {
	items[cur].console.PushBack([]byte(""))
	items[cur].changed = true
	cat()
}

func LineAppend(cryptic bool) {
	var s []byte
	fmt.Println(defaultPrompt)
	if cryptic {
		s = terminal.SecureInput(false)
	} else {
		s = terminal.PlainTextInput()
	}

	if s != nil {
		items[cur].console.PushBack(s)
		items[cur].changed = true
		cat()
	} else {
		fmt.Println(">>>>>>>>>>>>>> impossible error occured, please check src <<<<<<<<<<<<<<")
	}
}

func LineInsertSpace(arg []string) {
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

func LineInsert(arg []string, cryptic bool) {
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
		s = terminal.SecureInput(false)
	} else {
		s = terminal.PlainTextInput()
	}

	if s != nil {
		if insertLine(i, s) {
			cat()
		}
	}
}

func DeleteEmptyLines() {
	var found bool
	i := items[cur].console.Front()
	for i != nil {
		p := i
		i = i.Next()
		if len(p.Value.([]byte)) == 0 {
			deleteLine(cur, p)
			found = true
		}
	}

	if found {
		cat()
	} else {
		fmt.Println("Empty lines not found")
	}
}

func LinesDelete(arg []string) {
	indexes := parseAndSortIntArgs(arg)
	if indexes != nil {
		primitives.ReverseInt(indexes)
		for _, x := range indexes {
			deleteLineAtIndex(x)
		}
		cat()
	}
}

func LinesDeleteRange(arg []string) {
	indexes := parseAndSortIntArgs(arg)
	if len(indexes) == 2 {
		beg := indexes[0]
		end := indexes[1]
		primitives.ReverseInt(indexes)
		for i := end; i >= beg; i-- {
			deleteLineAtIndex(i)
		}
		cat()
	}
}

func LinesPrint(arg []string) {
	if len(items[cur].src) != 0 && items[cur].console.Len() == 0 {
		deriveConsoleFromSrc()
	}

	indexes := parseAndSortIntArgs(arg)
	total := len(indexes)
	if total == 0 {
		fmt.Println("Error: wrong index")
		return
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

func LinesPrintRange(arg []string) {
	indexes := parseAndSortIntArgs(arg)
	if len(indexes) != 2 {
		fmt.Println("Error: wrong indexes")
		return
	}

	beg := indexes[0]
	end := indexes[1]
	var ln int

	fmt.Println(Bar)
	for x := items[cur].console.Front(); x != nil; x = x.Next() {
		if ln >= beg && ln <= end {
			fmt.Printf("%03d│ %s\n", ln, x.Value.([]byte))
		}
		ln++
	}
	fmt.Println(Bar)
}

func LinesMerge(arg []string) {
	if len(arg) < 2 {
		fmt.Println(">>> Error: line number is missing ")
		return
	}

	i, ok := a2i(arg[1], 0, items[cur].console.Len()-1)
	if ok {
		if mergeLines(i) {
			cat()
		}
	}
}

func LineSplit(arg []string) {
	if len(arg) < 3 {
		fmt.Printf(">>> Error: three params expected, got %d \n", len(arg))
		return
	}

	ln, ok := a2i(arg[1], 0, items[cur].console.Len())
	if ok {
		pos, ok := a2i(arg[2], 0, 100000)
		if ok {
			if splitLine(ln, pos) {
				cat()
			}
		}
	}
}

func LineCut(arg []string) {
	if len(arg) < 3 {
		fmt.Printf(">>> Error: three params expected, got %d \n", len(arg))
		return
	}

	ln, ok := a2i(arg[1], 0, items[cur].console.Len())
	if ok {
		pos, ok := a2i(arg[2], 0, 100000)
		if ok {
			if cutLine(ln, pos) {
				cat()
			}
		}
	}
}

func LineExtend(arg []string, cryptic bool) {
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
		s = terminal.SecureInput(false)
	} else {
		s = terminal.PlainTextInput()
	}
	if s != nil {
		if extendLine(ln, s) {
			cat()
		}
	}
	crutils.AnnihilateData(s)
}

func info() {
	pos := [2]string{"face", "steg"}
	fmt.Printf("You are currently at %s \n", pos[cur])
	for i := range 2 {
		fmt.Printf("%s: %d lines, %d bytes \n", pos[i], items[i].console.Len(), getConsoleSizeInBytes(i))
	}
}

func switchContent() {
	cur = (cur + 1) % 2
	cat()
}

func clear() {
	for range 50 {
		fmt.Println()
	}
}
