package SecureInput

import (
	crand "crypto/rand"
	mrand "math/rand"
	"fmt"
	"time"
	"os"
	"os/exec"
	"crypto/sha256"
)

// you can always arbitrary extend the alphabet (add capital letters, special characters, etc.)
const alphabet string = "abcdefghijklmnopqrstuvwxyz 0123456789,."
const sz = len(alphabet)
var rndAlphabet string


func printSpaced(s string) {
	x := make([]byte, sz*2)
	for i, c := range s {
		x[i*2] = byte(c)
		x[i*2 + 1] = ' '
	}
	fmt.Print(string(x))
}

func readSafeInput() string {
	//fmt.Println("SecureInput version 24")
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
			res, done = recoverRandomizedByte(b[0])
			s += res
		}
	}

	fmt.Println()
	return s
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
	// shift
	rnd := randNum()
	rndAlphabet = alphabet[rnd:] + alphabet[:rnd]

	// shuffle
	var x []byte = []byte(rndAlphabet)
	perm := mrand.Perm(sz)
	for j, v := range perm {
		x[j] = rndAlphabet[v]
	}
	rndAlphabet = string(x)
}

func recoverRandomizedByte(c byte) (string, bool) {
	for i := 0; i < sz; i++ {
		if rndAlphabet[i] == c {
			r := alphabet[i]
			return string(r), false
		}
	}
	return "", true
}

func ReadFromTerminal() string {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run() // disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run() // do not display entered characters on the screen
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run() // restore the echoing state when exiting
	return readSafeInput()
}

//func ReadFromTerminalTst() string {
//	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
//	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
//	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()
//	var b []byte = make([]byte, 1)
//	for {
//		os.Stdin.Read(b)
//		fmt.Println("I got the byte", b, "(" + string(b) + ")")
//	}
//	return "test finished"
//}

/////////////////////////////////////////////////////////////////////////////////

func hash(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func SHash(s string) string {
	h := hash(s)
	x := fmt.Sprintf("%x", h)
	return x
}

func XHash() string {
	s := ReadFromTerminal()
	return SHash(s)
}
