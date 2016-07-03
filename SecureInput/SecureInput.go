package SecureInput

import (
	"fmt"
	"time"
	"os"
	"os/exec"
	crand "crypto/rand"
	mrand "math/rand"
)

const alphabet string = "abcdefghijklmnopqrstuvwxyz 0123456789"
const alphabetShift string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ )!@#$%^&*("
const sz = len(alphabet)

var rndAlphabet, rndAlphabetShift string

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
	rnd := randNum()
	if rnd >= sz {
		panic("weird error in randomizeAlphabet()")
	}
	rndAlphabet = alphabet[rnd:] + alphabet[:rnd]
	rndAlphabetShift = alphabetShift[rnd:] + alphabetShift[:rnd]

	// shuffle
	var x []byte = []byte(rndAlphabet)
	var xshift []byte = []byte(rndAlphabetShift)
	perm := mrand.Perm(sz)
	for j, v := range perm {
		x[j] = rndAlphabet[v]
		xshift[j] = rndAlphabetShift[v]
	}
	rndAlphabet = string(x)
	rndAlphabetShift = string(xshift)
}

func recoverRandomizedByte(c byte) string {
	if c >= 32 && c <= 122 {
		for i := 0; i < sz; i++ {
			if rndAlphabet[i] == c {
				r := alphabet[i]
				return string(r)
			}
		}
		for i := 0; i < sz; i++ {
			if rndAlphabetShift[i] == c {
				r := alphabet[i]
				if r >= 97 && r <= 122 {
					r -= 32
				}
				return string(r)
			}
		}
	}
	return ""
}

func printSpaced(s string) {
	x := make([]byte, sz*2)
	for i, c := range s {
		x[i*2] = byte(c)
		x[i*2 + 1] = ' '
	}
	fmt.Print(string(x))
}

func readSafeInput() string {
	//fmt.Println("version 14")
	printSpaced(alphabet)
	fmt.Println()
	var s string
	var b []byte = make([]byte, 1)
	for {
		randomizeAlphabet()
		fmt.Print("\r")
		printSpaced(rndAlphabet)
		os.Stdin.Read(b)

		if 127 == b[0] {
			if cur := len(s); cur > 0 {
				s = s[:cur - 1]
			}
		} else {
			res := recoverRandomizedByte(b[0])
			if len(res) == 0 {
				break
			}
			s += res
		}
	}
	fmt.Println()
	return s
}

func ReadFromTerminal() string {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run() // disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run() // do not display entered characters on the screen
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run() // restore the echoing state when exiting
	return readSafeInput()
}

func ReadFromTerminalTst() {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	var b []byte = make([]byte, 1)
	for {
		os.Stdin.Read(b)
		fmt.Println("I got the byte", b, "(" + string(b) + ")")
	}
}

