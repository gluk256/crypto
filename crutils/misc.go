package crutils

import (
	"time"
	"encoding/binary"

	"github.com/gluk256/crypto/algo/keccak"
)

func Reverse(a []int) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
		i++
		j--
	}
}

func CollectEntropy() []byte {
	b := make([]byte, 8)
	i := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(b, uint64(i))
	return b
}

func UpdateEntropy(h *keccak.Keccak512) {
	b := CollectEntropy()
	h.Write(b)
}
