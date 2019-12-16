package crutils

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
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
	b := make([]byte, 32)
	n, err := crand.Read(b)
	if err != nil || n != len(b) {
		fmt.Printf("Error in init: Crypto.Rand() failed: %s\n", err)
		os.Exit(0)
	}
	entropy.Write(b)
	CollectEntropy()
	entropy.Read(b)
	destructionProof.Write(b)
}

func CollectEntropy() {
	i := time.Now().UnixNano()
	entropy.AddEntropy(uint64(i))
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
	if err == nil && n != len(dst) {
		err = errors.New("failed to read from crand")
	}
	// even in case of errors, do your best
	mathrand := make([]byte, len(dst))
	_, err2 := mrand.Read(mathrand)
	if err == nil {
		err = err2
	}
	primitives.XorInplace(dst, mathrand, len(dst))
	RandXor(dst)
	AnnihilateData(mathrand)
	return err
}

// collect entropy from three independent sources
func StochasticUint64() (uint64, error) {
	b := make([]byte, 8)
	n, err := crand.Read(b)
	if err == nil && n != 8 {
		err = errors.New("failed to read from crand")
	}
	// even in case of errors, do your best
	x := binary.LittleEndian.Uint64(b)
	x ^= mrand.Uint64()
	x ^= entropy.RandUint64()
	return x, err
}

func PseudorandomUint64() uint64 {
	return entropy.RandUint64()
}

func AnnihilateData(b []byte) {
	if len(b) > 0 {
		RandXor(b)
		destructionProof.Write(b)
		if len(b) < 1024*1024 {
			// small data are likely to contain very sensitive info (e.g. RCX cryptographic setup),
			// and therefore it is important to prevent the compiler optimization.
			primitives.ReverseBytes(b)
			RandXor(b)
			destructionProof.Write(b)
		}
	}
}

func RecordDestruction(i uint64) {
	destructionProof.AddEntropy(i)
}

// this function should be called once, before the program exit
func ProveDataDestruction() {
	b := make([]byte, 1032)
	entropy.Read(b)
	destructionProof.Write(b)
	destructionProof.Read(b)
	fmt.Printf("\nProof of destruction: [%x]\n", b[1000:])
}

func GenerateRandomPassword(sz int) (res []byte, err error) {
	var arr = []byte("abcdefghijklmnopqrstuvwxyz0123456789") // you can add arbitrary ASCII characters
	res = make([]byte, 0, sz)
	for i := 0; i < sz; i++ {
		rnd, errX := StochasticUint64()
		c := arr[rnd%uint64(len(arr))]
		res = append(res, c)
		if errX != nil && err == nil {
			err = errX
		}
	}
	return res, err
}
