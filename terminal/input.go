package terminal

import (
	"bufio"
	"fmt"
	"time"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	crand "crypto/rand"
	mrand "math/rand"
	shell "golang.org/x/crypto/ssh/terminal"

	"github.com/gluk256/crypto/crutils"
)

var inputReader = bufio.NewReader(os.Stdin)
const sz = 39

// you can always arbitrary extend the alphabet (add capital letters, special characters, etc.)
// IMPORTANT: only ASCII characters are allowed
var alphabet = []byte("abcdefghijklmnopqrstuvwxyz 0123456789,.")
var scrambledAlphabet []byte = make([]byte, sz)

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
	if len(alphabet) != sz {
		panic("please fix the sz constant")
	}
	//fmt.Println("SecureInput version 26")
	printSpaced(alphabet)
	fmt.Println()
	b := make([]byte, 1)
	s := make([]byte, 0, 128)
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
		case  96: // '~': do nothing (reshuffle)
		case 126: // shift + '~': do nothing (reshuffle)
		case 127: // backspace
			if i := len(s); i > 0 {
				s = s[:i-1]
			}
		default:
			next, done = decryptByte(b[0])
			if !done {
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

func SecureInputLinux() []byte {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run() // disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run() // do not display entered characters on the screen
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run() // restore the echoing state when exiting
	defer exec.Command("stty", "-F", "/dev/tty", "icanon").Run()
	return secureRead()
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
		fmt.Println("I got the byte", b, "(" + string(b) + ")")
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

func StandardInput() []byte {
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

func SecureInput() []byte {
	if runtime.GOOS == "linux" {
		return SecureInputLinux()
	} else {
		return PasswordModeInput()
	}
}
