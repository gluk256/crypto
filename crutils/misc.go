package crutils

import (
	"time"
	"encoding/binary"

	"github.com/gluk256/crypto/algo/keccak"
)

var Entropy keccak.Keccak512

func ReverseInt(a []int) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
		i++
		j--
	}
}

func ReverseByte(a []byte) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
		i++
		j--
	}
}

func CollectEntropy() {
	b := make([]byte, 8)
	i := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(b, uint64(i))
	Entropy.Write(b)
}

func Rand(dst []byte, sz int) {
	Entropy.Read(dst, sz)
}

func RandXor(dst []byte, sz int) {
	rnd := make([]byte, sz)
	Entropy.Read(rnd, sz)
	keccak.XorInplace(dst, rnd, sz)
}

func Substitute(s []byte, prev byte, n byte) {
	for i := 0; i < len(s); i++ {
		if s[i] == prev {
			s[i] = n
		}
	}
}
