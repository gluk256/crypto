package crutils

import (
	"crypto/sha256"
	"fmt"
	"errors"
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

func Char2int(b byte) int {
	if b >= 48 && b <= 57 {
		return int(b - 48)
	}
	if b >= 65 && b <= 70 {
		return int(b - 65) + 10
	}
	if b >= 97 && b <= 102 {
		return int(b - 97) + 10
	}
	return -1
}

func HexDecode(src []byte) ([]byte, error) {
	for i := len(src) - 1; i >=0; i-- {
		if src[i] > 32 && src[i] < 128 {
			break
		} else {
			src = src[:len(src) - 1]
		}
	}

	sz := len(src)
	if sz % 2 == 1 {
		s := fmt.Sprintf("Error decoding: odd src size %d", sz)
		return nil, errors.New(s)
	}

	var dst []byte
	for i := 0; i < sz; i += 2 {
		a := Char2int(src[i])
		b := Char2int(src[i+1])
		if a < 0 || b < 0 {
			s := fmt.Sprintf("Error decoding: illegal byte [%s]", string(src[i:i+2]))
			return nil, errors.New(s)
		}
		dst = append(dst, byte(16*a+b))
	}
	return dst, nil
}
