package crutils

import (
	"fmt"
	"time"
	"encoding/binary"
	mrand "math/rand"
	crand "crypto/rand"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
)

var entropy keccak.Keccak512
var witness keccak.Keccak512
var accumulator = make([]byte, keccak.Rate)

func CollectEntropy() {
	b := make([]byte, 8)
	i := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(b, uint64(i))
	entropy.Write(b)
}

func Rand(dst []byte) {
	entropy.Read(dst)
	entropy.ReadXor(accumulator) // overwrite internal state
}

func RandXor(dst []byte) {
	entropy.ReadXor(dst)
	entropy.ReadXor(accumulator) // overwrite internal state
}

func StochasticRand(dst []byte) error {
	_, err := crand.Read(dst)
	if err == nil {
		mathrand := make([]byte, len(dst))
		_, err = mrand.Read(mathrand)
		primitives.XorInplace(dst, mathrand, len(dst))
		AnnihilateData(mathrand)
		RandXor(dst)
	}
	return err
}

func AnnihilateData(b []byte) {
	if len(b) > 0 {
		// overwrite; prevent compiler optimization
		RandXor(b)
		sz := len(b)
		div := int(b[sz-1] & 0x3) + 2
		primitives.ReverseBytes(b[sz/div:])
		witness.Write(b)
	}
}

// this function should be called before the program exits
func ProveDestruction() {
	b := make([]byte, 32)
	witness.Write(accumulator)
	witness.Read(b)
	fmt.Printf("proof of destruction: %x\n", b)
}

func RandPass(sz int) []byte {
	var arr = []byte("abcdefghijklmnopqrstuvwxyz0123456789") // you can add arbitrary chars
	var res []byte
	for i := 0; i < sz; i++ {
		b := make([]byte, len(arr))
		StochasticRand(b)
		var sum int
		for j := 0; j < len(arr); j++ {
			sum += int(b[j])
		}
		c := arr[sum % len(arr)]
		res = append(res, c)
	}
	return res
}
