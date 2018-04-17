package crutils

import (
	"time"
	"encoding/binary"

	"github.com/gluk256/crypto/algo/keccak"
)

var Entropy keccak.Keccak512

func Reverse(a []int) {
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

func Rand(out []byte, sz int) {
	Entropy.Read(out, sz)
}
