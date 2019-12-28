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

func addSpacing(data []byte, spacing []byte) []byte {
	b := make([]byte, 0, len(data)*2+256)
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
	requiredSize := sz
	if mark {
		requiredSize += 4
	}

	if newSize <= 0 {
		newSize = primitives.FindNextPowerOfTwo(requiredSize)
		if newSize < MinDataSize {
			newSize = MinDataSize
		}
	} else if newSize < requiredSize {
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
	newSize := int(a) + int(b)<<16
	if newSize > sz {
		return data, errors.New(fmt.Sprintf("error removing padding: wrong sizes [%d vs. %d]", newSize, sz))
	}
	return data[:newSize], nil
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	err := StochasticRand(salt)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Stochastic rand failed: %s", err.Error()))
	}
	return salt, err
}

func GenerateKeys(key []byte, salt []byte) []byte {
	fullkey := make([]byte, 0, len(key)+len(salt))
	fullkey = append(fullkey, key...)
	fullkey = append(fullkey, salt...)
	keyholder := keccak.Digest(fullkey, getKeyHolderSize())
	AnnihilateData(fullkey)
	return keyholder
}
