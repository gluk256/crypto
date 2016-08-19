package crutils

import (
	"fmt"
	"crypto/sha256"
	"github.com/gluk256/crypto/terminal"
)

func Hash(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func SHash(s string) string {
	h := Hash(s)
	x := fmt.Sprintf("%x", h)
	return x
}

func XHash() string {
	s := terminal.SecureInput()
	return SHash(s)
}
