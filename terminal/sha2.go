package terminal

import (
	"fmt"
	"crypto/sha256"
	//"github.com/gluk256/crypto/terminal"
)

func Sha2(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func SSha2(s string) string {
	h := Sha2(s)
	x := fmt.Sprintf("%x", h)
	return x
}

func XSha2() string {
	s := SecureInput()
	return SSha2(s)
}
