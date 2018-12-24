package crutils

import (
	"bytes"
	"testing"
	"time"
	mrand "math/rand"

	"github.com/gluk256/crypto/algo/primitives"
)

func TestRand(t *testing.T) {
	const sz = 1024
	sample := make([]byte, sz)
	b2 := make([]byte, sz)
	b3 := make([]byte, sz)
	b4 := make([]byte, sz)
	Rand(sample)
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

	Rand(b3)
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

func generateRandomBytes(t *testing.T) []byte {
	sz := mrand.Intn(256) + 256
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

	for i := 0; i < 1024; i++ {
		key := generateRandomBytes(t)
		x := generateRandomBytes(t)
		y := make([]byte, len(x))
		copy(y, x)

		EncryptKeccakInplace(key, y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		DecryptKeccakInplace(key, y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptSimplest(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 1024; i++ {
		key := generateRandomBytes(t)
		x := generateRandomBytes(t)
		y := make([]byte, len(x))
		copy(y, x)

		EncryptSimplestInplace(key, y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		EncryptSimplestInplace(key, y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}
