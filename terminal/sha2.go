package terminal

import (
	"crypto/sha256"
	"fmt"
)

func Sha2(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
}

func SSha2(s string) string {
	h := Sha2([]byte(s))
	x := fmt.Sprintf("%x", h)
	return x
}

//func XSha2() string {
//	s := SecureInput()
//	return Sha2(s)
//}

func PrintHashedInput() {
	s := SecureInput()
	hash := Sha2(s)
	fmt.Printf("%x", hash)
}
