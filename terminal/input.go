package terminal

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	shell "golang.org/x/crypto/ssh/terminal"

	"github.com/gluk256/crypto/crutils"
)

// you can arbitrary extend the alphabet with additional ASCII characters
var alphabetStandard = []byte("abcdefghijklmnopqrstuvwxyz 0123456789,.")
var alphabetExt = []byte("abcdefghijklmnopqrstuvwxyz 0123456789!@#$%^&*()_+-=[];'\\,./:\"|<>?~`")
var alphabet []byte
var scrambledAlphabet []byte
var sz = 0
var inputReader = bufio.NewReader(os.Stdin)

func printSpaced(s []byte) {
	var x string
	delim := string("│")
	for _, c := range s {
		x += string(c)
		x += delim
	}
	fmt.Print(x)
}

func shiftAlphabet() {
	rnd, err := crutils.StochasticUint64()
	if err != nil {
		panic("Error in randomizeAlphabet(): " + err.Error())
	}
	off := int(rnd % uint64(sz))
	for i, c := range alphabet {
		j := (i + off) % sz
		scrambledAlphabet[j] = c
	}
}

func shuffleAlphabet() {
	rnd := crutils.PseudorandomUint64()
	generator := rand.New(rand.NewSource(int64(rnd)))
	permutation := generator.Perm(sz)
	x := scrambledAlphabet
	for j, v := range permutation {
		x[j], x[v] = x[v], x[j]
	}
}

func randomizeAlphabet() {
	shiftAlphabet()
	shuffleAlphabet()
}

func initParams(ext bool) {
	if ext {
		alphabet = alphabetExt
	} else {
		alphabet = alphabetStandard
	}

	sz = len(alphabet)
	scrambledAlphabet = make([]byte, sz)
}

func resetParams() {
	sz = 0
	alphabet = nil
	scrambledAlphabet = nil
}

func secureRead(ext bool) []byte {
	initParams(ext)
	defer resetParams() // explicitly allow garbage collection
	printSpaced(alphabet)
	fmt.Println()
	b := make([]byte, 1)
	s := make([]byte, 0, 150)
	var next byte
	done := false

	for !done {
		randomizeAlphabet()
		fmt.Print("\r")
		printSpaced(scrambledAlphabet)
		_, err := os.Stdin.Read(b)
		if err != nil {
			fmt.Printf(">>>>>> Input Error: %s \n", err)
			return nil
		}

		switch b[0] {
		case 27: // escape: only reshuffle, do nothing
		case 127: // backspace
			if i := len(s); i > 0 {
				s = s[:i-1]
			}
		default:
			next, done = decryptByte(b[0])
			if !done && next != '`' {
				s = append(s, next)
			}
		}
		crutils.CollectEntropy()
	}

	fmt.Print("\r")
	printSpaced(alphabet)
	fmt.Println()
	return s
}

func decryptByte(c byte) (byte, bool) {
	for i := 0; i < sz; i++ {
		if scrambledAlphabet[i] == c {
			r := alphabet[i]
			return r, false
		}
	}
	return byte(0), true
}

func SecureInputLinux(ext bool) []byte {
	//fmt.Println("SecureInput version 32")
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run() // disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()              // do not display entered characters on the screen
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()         // restore the echoing state when exiting
	defer exec.Command("stty", "-F", "/dev/tty", "icanon").Run()
	return secureRead(ext)
}

func SecureInputTest() []byte {
	fmt.Println("test is running")
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	defer exec.Command("stty", "-F", "/dev/tty", "icanon").Run()
	var b []byte = make([]byte, 1)
	for b[0] != byte(1) { // Ctrl + a
		os.Stdin.Read(b)
		fmt.Println("I got the byte", b, "("+string(b)+")")
	}
	return []byte("test finished")
}

func PasswordModeInput() []byte {
	s, err := shell.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf(">>>>>> Input Error: %s \n", err)
		return nil
	}
	crutils.CollectEntropy()
	return s
}

func PlainTextInput() []byte {
	const n = byte('\n')
	txt, err := inputReader.ReadBytes(n)
	if err != nil {
		fmt.Printf(">>>>>> Input Error: %s \n", err)
		return nil
	}
	last := len(txt) - 1
	if last >= 0 && txt[last] == n {
		txt = txt[:last]
	}
	crutils.CollectEntropy()
	return txt
}

func SecureInput(ext bool) []byte {
	if runtime.GOOS == "linux" {
		return SecureInputLinux(ext)
	} else {
		return PasswordModeInput()
	}
}
