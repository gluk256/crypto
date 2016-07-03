package SecureInput

import (
	"fmt"
	"time"
	"os"
	"os/exec"
	"crypto/rand"
)

const alphabet string = "abcdefghijklmnopqrstuvwxyz 0123456789"
const alphabetShift string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ )!@#$%^&*("
const sz = len(alphabet)

var rndAlphabet, rndAlphabetShift string

func randNum(prev int) int {
	sum := time.Now().Nanosecond()
	stochastic := make([]byte, sz)
	j, err := rand.Read(stochastic)
	if err != nil || j != sz {
		panic("error in randNum(): " + err.Error())
	}
	for _, j := range(stochastic) {
		sum += int(j)
	}
	return sum % sz
}

func randomizeAlphabet(rnd int) {
	if rnd >= sz {
		panic("randomizeAlphabet: wtf??")
	}
	rndAlphabet = alphabet[rnd:] + alphabet[:rnd]
	rndAlphabetShift = alphabetShift[rnd:] + alphabetShift[:rnd]
}

func convertRandomizedByte(c byte) string {
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

func readSafeInput() string {
	fmt.Println(alphabet)
	var s string
	var b []byte = make([]byte, 1)
	rnd := 0
	for {
		fmt.Print("\r")
		rnd = randNum(rnd)
		randomizeAlphabet(rnd)
		fmt.Print(rndAlphabet + " ")
		os.Stdin.Read(b)
		if 127 == b[0] {
			if cur := len(s); cur > 0 {
				s = s[:cur - 1]
			}
		} else {
			res := convertRandomizedByte(b[0])
			if len(res) == 0 {
				break
			}
			s += res
		}
	}
	return s
}

func ReadFromTerminal() string {
	// disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	// do not display entered characters on the screen
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	// restore the echoing state when exiting
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()

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

