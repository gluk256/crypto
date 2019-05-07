package crutils

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/algo/rcx"
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

func addSpacing(data []byte, spacing []byte) []byte {
	b := make([]byte, 0, len(data)*2)
	for i := 0; i < len(data); i++ {
		b = append(b, data[i])
		b = append(b, spacing[i])
	}
	AnnihilateData(data)
	AnnihilateData(spacing)
	return b
}

func splitSpacing(data []byte) ([]byte, []byte) {
	b := make([]byte, 0, len(data)/2)
	s := make([]byte, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		b = append(b, data[i])
		if i+1 < len(data) {
			s = append(s, data[i+1])
		}
	}
	AnnihilateData(data)
	return b, s
}

// the size of content before encryption must be power of two
func addPadding(data []byte, newSize int, mark bool) ([]byte, error) {
	sz := len(data)
	if newSize <= 0 {
		newSize = primitives.FindNextPowerOfTwo(sz + 4)
		if newSize < MinDataSize {
			newSize = MinDataSize
		}
	} else if newSize < sz + 4 {
		return data, errors.New("padding failed: new size is too small")
	}
	rnd := make([]byte, newSize)
	Randomize(rnd)
	copy(rnd, data)
	AnnihilateData(data)
	data = rnd
	if mark {
		b := uint16(uint32(sz) >> 16)
		a := uint16(sz)
		data[newSize-2], data[newSize-1] = rcx.Uint2bytes(b)
		data[newSize-4], data[newSize-3] = rcx.Uint2bytes(a)
	}
	return data, nil
}

func removePadding(data []byte) ([]byte, error) {
	sz := len(data)
	if sz < 4 {
		return data, errors.New("Can not remove padding")
	}
	b := rcx.Bytes2uint(data[sz-2], data[sz-1])
	a := rcx.Bytes2uint(data[sz-4], data[sz-3])
	newSize := int(a) + int(b) << 16
	if newSize > sz {
		return data, errors.New(fmt.Sprintf("error removing padding: wrong sizes [%d vs. %d]", newSize, sz))
	}
	return data[:newSize], nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	err := StochasticRand(salt)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Stochastic rand failed: %s", err.Error()))
	}
	return salt, err
}

func generateKeys(key []byte, salt []byte) []byte {
	fullkey := make([]byte, 0, len(key) + len(salt))
	fullkey = append(fullkey, key...)
	fullkey = append(fullkey, salt...)
	keyholder := keccak.Digest(fullkey, keyHolderSize)
	AnnihilateData(fullkey)
	return keyholder
}
