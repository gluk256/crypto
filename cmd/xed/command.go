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

func processCommand(cmd string, prev string) string {
	args := strings.Fields(cmd)
	if len(args) == 0 {
		return prev
	}

	switch args[0] {
	case "rr":
		return processCommand(prev, prev)
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
	case "cat":
		cat()
	case "cc":
		cat()
	case "fd": // file decrypt
		if FileLoad(args, false) {
			contentDecrypt(true, false)
		}
	case "fdp": // file decrypt
		if FileLoad(args, false) {
			contentDecrypt(false, false)
		}
	case "fD": // file decrypt
		if FileLoad(args, false) {
			contentDecrypt(true, true)
		}
	case "fDp": // file decrypt
		if FileLoad(args, false) {
			contentDecrypt(false, true)
		}
	case "fl": // file load
		FileLoad(args, false)
	case "fo": // file open (print text without decrypting)
		FileLoad(args, true)
	case "fs": // file encrypt & save
		FileSave(true)
	case "fp": // file encrypt & save
		FileSave(false)
	case "fx": // file save steg
		FileSaveSteg(true, true)
	case "fpx": // file save steg
		FileSaveSteg(false, true)
	case "fpp": // file save steg
		FileSaveSteg(false, false)
	case "cd":
		contentDecrypt(true, false)
	case "cdp":
		contentDecrypt(false, false)
	case "cD":
		contentDecrypt(true, true)
	case "cDp":
		contentDecrypt(false, true)
	case "xd":
		stegDecrypt(true, false)
	case "xdp":
		stegDecrypt(false, false)
	case "xD":
		stegDecrypt(true, true)
	case "xDp":
		stegDecrypt(false, true)
	case "grep":
		grep(args, false, false)
	case "g":
		grep(args, true, false)
	case "G":
		grep(args, true, true)
	case "a": // editor: append line to the end
		LineAppend(false)
	case "A": // editor: append line with cryptic input
		LineAppend(true)
	case "i": // editor: insert line at certain index
		LineInsert(args, false)
	case "I": // editor: insert line cryptic
		LineInsert(args, true)
	case "e": // editor: extend line (append to the end of line)
		LineExtend(args, false)
	case "E": // editor: extend line cryptic
		LineExtend(args, true)
	case "c": // editor: cut line (delete from the end)
		LineCut(args)
	case "b": // editor: insert empty line
		LineInsertSpace(args)
	case "d": // editor: delete lines
		LinesDelete(args)
	case "D": // editor: delete lines range
		LinesDeleteRange(args)
	case "L": // editor: delete all empty lines
		DeleteEmptyLines()
	case "m": // editor: merge lines
		LinesMerge(args)
	case "s": // editor: split lines
		LineSplit(args)
	case "p": // editor: print lines
		LinesPrint(args)
	case "P": // editor: print lines range
		LinesPrintRange(args)
	default:
		fmt.Printf(">>> Wrong command: '%s' [%x] \n", cmd, []byte(cmd))
	}

	return cmd
}

func helpInternal() {
	fmt.Println("COMMANDS")
	fmt.Println("help:\t display this help")
	fmt.Println("rr:\t repeat the previous command")
	fmt.Println("info:\t display diagnostic info")
	fmt.Println("clear:\t wipe the screen")
	fmt.Println("frame:\t change frame style")
	fmt.Println("reset:\t reset current content")
	fmt.Println("sw:\t switch content")
	fmt.Println("ls:\t list current directory contents")
	fmt.Println("cat:\t print content")
	fmt.Println("fl:\t file load")
	fmt.Println("fo:\t file load and print content without decrypting")
	fmt.Println("fd:\t file load and decrypt")
	fmt.Println("fdp:\t file load and decrypt (password mode)")
	fmt.Println("fD:\t file load and decrypt (silent)")
	fmt.Println("fDp:\t file load and decrypt (silent, password mode)")
	fmt.Println("fs:\t file encrypt & save (face)")
	fmt.Println("fp:\t file encrypt & save (password mode)")
	fmt.Println("fx:\t file encrypt & save steg")
	fmt.Println("fpx:\t file encrypt & save steg (face: password mode)")
	fmt.Println("fpp:\t file encrypt & save steg (password mode)")
	fmt.Println("cd:\t decrypt loaded content")
	fmt.Println("cdp:\t decrypt loaded content (password mode)")
	fmt.Println("cD:\t decrypt loaded content (silent)")
	fmt.Println("cDp:\t decrypt loaded content (silent, password mode)")
	fmt.Println("xd:\t decrypt steg content")
	fmt.Println("xdp:\t decrypt steg content (password mode)")
	fmt.Println("xD:\t decrypt steg content (silent)")
	fmt.Println("xDp:\t decrypt steg content (silent, password mode)")
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
	fmt.Println("D:\t delete lines range")
	fmt.Println("L:\t delete all empty lines")
	fmt.Println("m:\t merge lines")
	fmt.Println("s:\t split a line")
	fmt.Println("p:\t print lines")
	fmt.Println("P:\t print lines range")
}

func help() {
	fmt.Printf("xed v.2.%d \n", crutils.CipherVersion)
	fmt.Println("editor for encrypted files and/or steganographic content")
	fmt.Println("USAGE: xed [decrytpion_flags] [srcFile] [dstFile]")
	fmt.Println("\td default decryption")
	fmt.Println("\tp password mode")
	fmt.Println("\tD mute")
	fmt.Println("\th help")
}

func info() {
	pos := [2]string{"face", "steg"}
	fmt.Printf("xed v.2.%d.102 \n", crutils.CipherVersion)
	fmt.Printf("You are currently at %s \n", pos[cur])
	fmt.Printf("face: %d lines, steg: %d lines \n", items[0].console.Len(), items[1].console.Len())
}
