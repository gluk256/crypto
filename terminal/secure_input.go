package terminal

import (
	crand "crypto/rand"
	mrand "math/rand"
	"fmt"
	"time"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	shell "golang.org/x/crypto/ssh/terminal"

	"github.com/gluk256/crypto/crutils"
)

// you can always arbitrary extend the alphabet (add capital letters, special characters, etc.)
// IMPORTANT: only ASCII characters are allowed
var alphabet = []byte("abcdefghijklmnopqrstuvwxyz 0123456789,.")
var sz = len(alphabet)
var scrambledAlphabet []byte

func printSpaced(s []byte) {
	var x string
	delim := string("│")
	for _, c := range s {
		x += string(c)
		x += delim
	}
	fmt.Print(x)
}

func randNum() int {
	sum := time.Now().Nanosecond()
	stochastic := make([]byte, sz)
	j, err := crand.Read(stochastic)
	if err != nil || j != sz {
		panic("error in randNum(): " + err.Error())
	}
	for _, j := range(stochastic) {
		sum += int(j)
	}
	return sum % sz
}

func randomizeAlphabet() {
	// shift with crand + local entropy
	rnd := randNum()
	for i, c := range alphabet {
		scrambledAlphabet[(i+rnd)%sz] = c
	}

	// shuffle with mrand
	perm := mrand.Perm(sz)
	x := scrambledAlphabet
	for j, v := range perm {
		x[j], x[v] = x[v], x[j]
	}
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

func secureRead() []byte {
	//fmt.Println("SecureInput version 26")
	printSpaced(alphabet)
	fmt.Println()
	var next byte
	b := make([]byte, 1)
	s := make([]byte, 0, 128)
	done := false

	for !done {
		randomizeAlphabet()
		fmt.Print("\r")
		printSpaced(scrambledAlphabet)
		os.Stdin.Read(b)

		switch b[0] {
		case  96: // '~': do nothing (reshuffle)
		case 126: // shift + '~': do nothing (reshuffle)
		case 127: // backspace
			if i := len(s); i > 0 {
				s = s[:i-1]
			}
		default:
			next, done = decryptByte(b[0])
			s = append(s, next)
		}

		crutils.CollectEntropy()
	}

	fmt.Print("\r")
	printSpaced(alphabet)
	fmt.Println()
	return s
}

func SecureInputLinux() []byte {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run() // disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run() // do not display entered characters on the screen
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run() // restore the echoing state when exiting
	return secureRead()
}

func SecureInputTest() []byte {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	var b []byte = make([]byte, 1)
	for {
		os.Stdin.Read(b)
		fmt.Println("I got the byte", b, "(" + string(b) + ")")
	}
	return []byte("test finished")
}


func PasswordModeInput() []byte {
	fmt.Print("Please enter the key: ")
	s, err := shell.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error: %s \n", err)
		os.Exit(0)
	}
	crutils.CollectEntropy()
	return s
}

func SecureInput() []byte {
	if runtime.GOOS == "linux" {
		return SecureInputLinux()
	} else {
		return PasswordModeInput()
	}
}
