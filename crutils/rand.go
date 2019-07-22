package crutils

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"os"
	"time"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
)

var entropy keccak.Keccak512
var destructionProof keccak.Keccak512

func init() {
	r := make([]byte, 32)
	n, err := crand.Read(r)
	if err != nil || n != len(r) {
		fmt.Printf("Error in init: Crypto.Rand() failed: %s\n", err)
		os.Exit(0)
	}
	entropy.Write(r)
}

func CollectEntropy() {
	b := make([]byte, 8)
	i := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(b, uint64(i))
	entropy.Write(b)
}

func Randomize(dst []byte) {
	entropy.Read(dst)
}

func RandXor(dst []byte) {
	entropy.ReadXor(dst)
}

// collect entropy from three independent sources
func StochasticRand(dst []byte) error {
	n, err := crand.Read(dst)
	if err == nil && n == len(dst) {
		mathrand := make([]byte, len(dst))
		_, err = mrand.Read(mathrand)
		primitives.XorInplace(dst, mathrand, len(dst))
		RandXor(dst)
		AnnihilateData(mathrand)
	}
	return err
}

func AnnihilateData(b []byte) {
	if len(b) > 0 {
		RandXor(b)
		destructionProof.Write(b)
		destructionProof.ReadXor(b)
		destructionProof.Write(b)
	}
}

// this function should be called before the program exits
func ProveDestruction() {
	b := make([]byte, 256)
	destructionProof.Read(b)
	fmt.Printf("Proof of destruction: %x\n", b[224:])
}

func GenerateRandomPassword(sz int) []byte {
	var arr = []byte("abcdefghijklmnopqrstuvwxyz0123456789") // you can add arbitrary ASCII characters
	var res []byte
	for i := 0; i < sz; i++ {
		b := make([]byte, len(arr))
		StochasticRand(b)
		var sum int
		for j := 0; j < len(arr); j++ {
			sum += int(b[j])
		}
		c := arr[sum%len(arr)]
		res = append(res, c)
	}
	return res
}
