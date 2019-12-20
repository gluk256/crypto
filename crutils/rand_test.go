package crutils

import (
	"bytes"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/algo/rcx"
)

func TestRand(t *testing.T) {
	const sz = 1024
	sample := make([]byte, sz)
	b2 := make([]byte, sz)
	b3 := make([]byte, sz)
	b4 := make([]byte, sz)
	Randomize(sample)
	copy(b2, sample)
	copy(b3, sample)
	copy(b4, sample)
	if !bytes.Equal(sample, b2) || !bytes.Equal(sample, b3) || !bytes.Equal(sample, b4) {
		t.Fatal("copy failed")
	}

	RandXor(b2)
	if bytes.Equal(b2, sample) {
		t.Fatal("RandXor failed")
	}
	ok := primitives.IsDeepNotEqual(sample, b2, sz)
	if !ok {
		t.Fatal("RandXor failed deep check")
	}

	Randomize(b3)
	if bytes.Equal(b3, sample) {
		t.Fatal("Rand failed")
	}
	ok = primitives.IsDeepNotEqual(sample, b3, sz)
	if !ok {
		t.Fatal("Rand failed deep check")
	}

	StochasticRand(b4)
	if bytes.Equal(b4, sample) {
		t.Fatal("Rand failed")
	}
	ok = primitives.IsDeepNotEqual(sample, b4, sz)
	if !ok {
		t.Fatal("Rand failed deep check")
	}
}

func generateRandomBytes(t *testing.T, big bool) []byte {
	sz := mrand.Intn(256) + 256
	if big {
		sz += mrand.Intn(1024 * 32)
	}
	b := make([]byte, sz)
	_, err := mrand.Read(b)
	if err != nil {
		t.Fatal("failed to generate random bytes")
	}
	return b
}

func generateRandomBytesMinSize(t *testing.T, minsize int) []byte {
	sz := mrand.Intn(256) + minsize
	b := make([]byte, sz)
	_, err := mrand.Read(b)
	if err != nil {
		t.Fatal("failed to generate random bytes")
	}
	return b
}

func TestEncryptKeccak(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 16; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		copy(y, x)

		EncryptInplaceKeccak(key, y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		EncryptInplaceKeccak(key, y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptSimplest(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 3; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		copy(y, x)

		rcx.EncryptInplaceRC4(key, y)
		EncryptInplaceKeccak(key, y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		rcx.EncryptInplaceRC4(key, y)
		EncryptInplaceKeccak(key, y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func TestAnnihilateData(t *testing.T) {
	seed := time.Now().Unix()
	var hash keccak.Keccak512
	hash.AddEntropy(uint64(seed))
	sz := 3 * 1024 * 1024
	x := make([]byte, sz)
	y := make([]byte, sz)
	hash.Read(x)
	copy(y, x)
	AnnihilateData(x)
	if !primitives.IsDeepNotEqual(x, y, sz) {
		t.Fatalf("AnnihilateData failed, with seed %d", seed)
	}
	sz /= 4
}
