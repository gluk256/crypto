package crutils

import "crypto/sha256"

func Sha2(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
}