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
const alphabet string = "abcdefghijklmnopqrstuvwxyz 0123456789,."

const sz = len(alphabet)
var rndAlphabet string


func printSpaced(s string) {
	var x string
	r := string("│")
	for _, c := range s {
		x += string(c)
		x += r
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
	// shift with crand
	rnd := randNum()
	rndAlphabet = alphabet[rnd:] + alphabet[:rnd]

	// shuffle with mrand
	var x []byte = []byte(rndAlphabet)
	perm := mrand.Perm(sz)
	for j, v := range perm {
		x[j] = rndAlphabet[v]
	}
	rndAlphabet = string(x)
}

func decryptByte(c byte) (string, bool) {
	for i := 0; i < sz; i++ {
		if rndAlphabet[i] == c {
			r := alphabet[i]
			return string(r), false
		}
	}
	return "", true
}

func secureRead() string {
	//fmt.Println("SecureInput version 25")
	printSpaced(alphabet)
	fmt.Println()
	var s, res string
	var b []byte = make([]byte, 1)
	done := false

	for !done {
		randomizeAlphabet()
		fmt.Print("\r")
		printSpaced(rndAlphabet)
		os.Stdin.Read(b)

		switch b[0] {
		case  96: // '~': do nothing (reshuffle)
		case 126: // shift + '~': do nothing (reshuffle)
		case 127: // backspace
			if i := len(s); i > 0 {
				s = s[:i-1]
			}
		default:
			res, done = decryptByte(b[0])
			s += res
		}

		crutils.CollectEntropy()
	}

	fmt.Print("\r")
	printSpaced(alphabet)
	fmt.Println()
	return s
}

func SecureInputLinux() string {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run() // disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run() // do not display entered characters on the screen
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run() // restore the echoing state when exiting
	return secureRead()
}

func SecureInputTest() string {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	var b []byte = make([]byte, 1)
	for {
		os.Stdin.Read(b)
		fmt.Println("I got the byte", b, "(" + string(b) + ")")
	}
	return "test finished"
}


func PasswordModeInput() string {
	fmt.Print("Please enter the key: ")
	key, err := shell.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error: %s \n", err)
		os.Exit(0)
	}
	crutils.CollectEntropy()
	return string(key)
}

func SecureInput() string {
	if runtime.GOOS == "linux" {
		return SecureInputLinux()
	} else {
		return PasswordModeInput()
	}
}
