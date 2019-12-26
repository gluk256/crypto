package main

import (
	"fmt"
	"strings"

	"github.com/gluk256/crypto/crutils"
)

func switchContent() {
	cur = (cur + 1) % 2
	cat()
}

func clear() {
	for i := 0; i < 50; i++ {
		fmt.Println()
	}
}

func processCommand(cmd string) {
	arg := strings.Fields(cmd)
	if len(arg) == 0 {
		return
	}

	switch arg[0] {
	case "h":
		helpInternal()
	case "help":
		helpInternal()
	case "clear":
		clear()
	case "frame":
		ChangeFrameStyle()
		cat()
	case "reset":
		reset(false)
	case "switch":
		switchContent()
	case "sw":
		switchContent()
	case "info":
		info()
	case "ls":
		ls()
	////////////////////////////////////////////
	case "cat": // content display current
		cat()
	case "cc": // content display current
		cat()
	case "cds": // content decrypt steg
		stegDecrypt(arg)
	case "cdd": // content decrypt steg
		stegDecrypt(arg)
	case "cd": // content decrypt
		contentDecrypt(arg)
	////////////////////////////////////////////
	case "fd": // file decrypt
		if FileLoad(arg, false) {
			contentDecrypt(arg)
		}
	case "fl": // file load
		FileLoad(arg, false)
	case "fo": // file open (print text without decrypting)
		FileLoad(arg, true)
	case "fs": // file save (encrypted)
		FileSave(arg)
	case "fss": // file save steg
		FileSaveSteg(arg)
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
	case "e": // editor: extend line (append to the end of line)
		LineExtend(arg, false)
	case "E": // editor: extend line cryptic
		LineExtend(arg, true)
	case "c": // editor: cut line (delete from the end)
		LineCut(arg)
	case "b": // editor: insert empty line
		LineInsertSpace(arg)
	case "d": // editor: delete lines
		LinesDelete(arg)
	case "m": // editor: merge lines
		LinesMerge(arg)
	case "s": // editor: split lines
		LineSplit(arg)
	case "p": // editor: print lines
		LinesPrint(arg)
	////////////////////////////////////////////
	default:
		fmt.Printf(">>> Wrong command: '%s' [%x] \n", cmd, []byte(cmd))
	}
}

func helpInternal() {
	fmt.Println("COMMANDS")
	fmt.Println("help:\t display this help")
	fmt.Println("info:\t display diagnostic info")
	fmt.Println("clear:\t wipe the screen")
	fmt.Println("frame:\t ChangeFrameStyle")
	fmt.Println("reset:\t reset current content")
	fmt.Println("sw:\t switch content")
	fmt.Println("ls:\t list current directory contents")
	fmt.Println("cat:\t print content")
	fmt.Println("cd:\t content decrypt")
	fmt.Println("cds:\t content decrypt steg")
	fmt.Println("fd:\t file load and decrypt")
	fmt.Println("fl:\t file load")
	fmt.Println("fo:\t file open and print content without decrypting")
	fmt.Println("fs:\t file save")
	fmt.Println("fss:\t file save steg")
	fmt.Println("fplain:\t file save as plain text")
	fmt.Println("grep:\t normal grep")
	fmt.Println("g:\t grep in password mode")
	fmt.Println("G:\t grep in secure mode")
	fmt.Println("a:\t append line to the end of file")
	fmt.Println("A:\t append line (secure input)")
	fmt.Println("i:\t insert line at certain index")
	fmt.Println("I:\t insert line (secure input)")
	fmt.Println("e:\t extend line (append to the end of certain line)")
	fmt.Println("E:\t extend line (secure input)")
	fmt.Println("c:\t cut line (delete from the end)")
	fmt.Println("b:\t insert empty line")
	fmt.Println("d:\t delete lines")
	fmt.Println("m:\t merge lines")
	fmt.Println("s:\t split lines")
	fmt.Println("p:\t print lines")
}

func help() {
	fmt.Printf("xedit v.2.%d \n", crutils.CipherVersion)
	fmt.Println("editor for encrypted files and/or steganographic content")
	fmt.Println("USAGE: xedit [flags] [srcFile] [dstFile]")
}

func info() {
	fmt.Printf("cur = %d, steg = %d \n", cur, steg)
	fmt.Printf("len(0) = %d, len(1) = %d, \n", len(items[0].src), len(items[1].src))
}
