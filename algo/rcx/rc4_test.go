package rcx

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
	mrand "math/rand"

	"github.com/gluk256/crypto/algo/primitives"
)

const iterations = 1025 // must be odd

func TestKeyStream(t *testing.T) {
	testSingleKeyStream(t, "Key", "EB9F7781B734CA72A719")
	testSingleKeyStream(t, "Wiki", "6044DB6D41B7")
	testSingleKeyStream(t, "Secret", "04D46B053CA87B59")

	testSingleEncrypt(t, "Key", "Plaintext", "BBF316E8D940AF0AD3")
	testSingleEncrypt(t, "Wiki", "pedia", "1021BF0420")
	testSingleEncrypt(t, "Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5")

	var k []byte
	for i := 0; i < 32; i++ {
		k = append(k, byte(i+1))
	}

	testSingleKeyStream(t, string(k), "eaa6bd25880bf93d3f5d1e4ca2611d91cfa45c9f7e714b54bdfa80027cb14380")
	testSingleKeyStream(t, string(k[:24]), "0595e57fe5f0bb3c706edac8a4b2db11dfde31344a1af769c74f070aee9e2326")
}

func testSingleKeyStream(t *testing.T, key string, expected string) {
	data := make([]byte, len(expected)/2)
	exp := make([]byte, len(expected)/2)
	hex.Decode(exp, []byte(expected))

	var r RC4
	r.InitKey([]byte(key))
	r.XorInplace(data)
	if !bytes.Equal(data, exp) {
		t.Fatalf("wrong keystream, key: %s", key)
	}
}

func testSingleEncrypt(t *testing.T, key string, data string, expected string) {
	d := []byte(data)
	exp := make([]byte, len(expected)/2)
	hex.Decode(exp, []byte(expected))

	var r RC4
	r.InitKey([]byte(key))
	r.XorInplace(d)
	if !bytes.Equal(d, exp) {
		t.Fatalf("encryption failed, key: %s", key)
	}
}

func generateRandomBytes(t *testing.T, align bool) []byte {
	sz := mrand.Intn(256) + 256
	if align {
		for sz%4 != 0 {
			sz++
		}
	}
	b := make([]byte, sz)
	_, err := mrand.Read(b)
	if err != nil {
		t.Fatal("failed to generate random bytes")
	}
	return b
}

func TestEncryptionRC4(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 256; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, false)
		y := make([]byte, len(x))
		copy(y, x)

		var re, rd RC4
		re.InitKey(key)
		rd.InitKey(key)

		re.XorInplace(y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		rd.XorInplace(y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func TestRollover(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 64; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, false)
		y := make([]byte, len(x))
		copy(y, x)

		rollover := mrand.Int() % 16000
		EncryptInplaceRC4(key, y, rollover)
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		EncryptInplaceRC4(key, y, rollover)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func TestConversion(t *testing.T) {
	a := byte(0xad)
	b := byte(0xde)
	v := Bytes2uint(a, b)
	if v != 0xDEAD {
		t.Fatalf("Bytes2uint failed, val = %x", v)
	}
	y, z := Uint2bytes(v)
	if y != a || z != b {
		t.Fatalf("Uint2bytes failed [%x, %x, %x, %x]", a, b, y, z)
	}
	v = Bytes2uint(0xa1, 0x0f)
	if v != 0x0FA1 {
		t.Fatalf("Bytes2uint failed second run, val = %x", v)
	}
	y, z = Uint2bytes(v)
	if y != 0xa1 || z != 0x0f {
		t.Fatalf("Uint2bytes failed second run [%x, %x, %x, %x]", a, b, y, z)
	}
}

func TestSingleRunRCX(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		copy(y, x)

		var cipher RCX
		cipher.InitKey(key)

		cipher.encryptSingleRun(y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		cipher.encryptSingleRun(y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

// encrypt array containing zeros
func TestSingleRunRcxZero(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)
	const sz = 1024 * 64

	for i := 0; i < 8; i++ {
		key := generateRandomBytes(t, false)
		x := make([]byte, sz)
		zero := make([]byte, sz)

		var cipher RCX
		cipher.InitKey(key)
		cipher.encryptSingleRun(x)
		ok := primitives.IsDeepNotEqual(x, zero, sz)
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		cipher.EncryptCascade(x, 255)
		ok = primitives.IsDeepNotEqual(x, zero, sz)
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}
	}
}

func TestCascade(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		copy(y, x)

		var c RCX
		c.InitKey(key)

		c.EncryptCascade(y, iterations)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		c.EncryptCascade(y, iterations)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func TestAvalancheRcx(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		z := make([]byte, len(x))
		copy(y, x)
		copy(z, x)

		var cipher RCX
		cipher.InitKey(key)

		x[0]-- // change at least one bit, which is supposed to cause an avalanche effect
		cycles := len(x)/2
		cipher.EncryptCascade(x, cycles)
		cipher.EncryptCascade(y, cycles)
		cipher.EncryptCascade(z, cycles)

		if !bytes.Equal(y, z) {
			t.Fatalf("failed to encrypt, round %d with seed %d", i, seed)
		}

		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed deep check, round %d with seed %d and len=%d", i, seed, len(x))
		}
	}
}

func TestAvalancheRC4(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 1024; i++ {
		var done bool
		var a, b RC4

		key := generateRandomBytes(t, false)
		a.InitKey(key)
		b.InitKey(key)
		k := byte(mrand.Int())
		n := byte(mrand.Int())
		if k == n {
			n++
		}
		b.s[k], b.s[n] = b.s[n], b.s[k] // swap two random elements

		// usually it takes no more than 3 iterations, but we allow 8
		for j := 0; j < 8; j++ {
			y := make([]byte, 256)
			x := make([]byte, 256)
			a.XorInplace(x)
			b.XorInplace(y)
			done = primitives.IsDeepNotEqual(x, y, len(x))
			if done {
				break
			}
		}
		if !done {
			t.Fatalf("failed with seed %d", seed)
		}
	}
}

func TestEncryptionRCX(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, false)
		y := make([]byte, len(x))
		copy(y, x)

		EncryptInplaceRCX(key, y, iterations, true)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		EncryptInplaceRCX(key, y, iterations, false)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d\n%x\n%x", i, seed, x, y)
		}
	}
}

// rcx encryption with zero iterations is supposed to be equal to rc4 encryption
func TestEncryptionRcxZero(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		z := make([]byte, len(x))
		copy(y, x)
		copy(z, x)

		arr := make([]byte, 256*256*64)
		var cipher RC4
		cipher.InitKey(key)
		cipher.XorInplace(arr)
		cipher.XorInplace(z)

		EncryptInplaceRCX(key, y, 0, true)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}
		if !bytes.Equal(y, z) {
			t.Fatalf("y != z, round %d with seed %d", i, seed)
		}
	}
}

// tests the ability to generate consistent gamma
func TestConsistencyRC4(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)
	b := make([]byte, 1024)
	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		sz := Bytes2uint(key[0], key[1])
		x := make([]byte, sz)
		y := make([]byte, sz)

		var r1, r2 RC4
		r1.InitKey(key)
		r2.InitKey(key)

		for j := 0; j < 170; j++ {
			r1.XorInplace(b[:33])
		}
		for j := 0; j < 330; j++ {
			r2.XorInplace(b[:17])
		}

		r1.XorInplace(x)
		r2.XorInplace(y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed to generate consistent gamma, round %d with seed %d", i, seed)
		}
	}
}
