package crutils

import (
	"crypto/sha256"
	"fmt"
)

func Sha2(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
}

func Sha2s(s []byte) string {
	h := Sha2(s)
	x := fmt.Sprintf("%x", h)
	return x
}
