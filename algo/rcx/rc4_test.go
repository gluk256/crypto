package rcx

import (
	"encoding/hex"
	"testing"
	"bytes"
	"time"
	mrand "math/rand"

	"github.com/gluk256/crypto/algo/primitives"
)

const iterations = 1025

func TestKeyStream(t *testing.T) {
	testSingleKeyStream(t, "Key", "EB9F7781B734CA72A719")
	testSingleKeyStream(t, "Wiki", "6044DB6D41B7")
	testSingleKeyStream(t, "Secret", "04D46B053CA87B59")

	testSingleEncrypt(t, "Key", "Plaintext", "BBF316E8D940AF0AD3")
	testSingleEncrypt(t, "Wiki", "pedia", "1021BF0420")
	testSingleEncrypt(t, "Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5")
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
	// seed := 1525474555 is a special case
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		copy(y, x)

		var cipher RCX
		cipher.InitKey(key)

		cipher.encryptSingleIteration(y)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		cipher.decryptSingleIteration(y)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
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

		c.encryptCascade(y, iterations)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		c.decryptCascade(y, iterations)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d", i, seed)
		}
	}
}

func BenchmarkRCX(b *testing.B) {
	key := "7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
	y := make([]byte, 1000000)
	var cipher RCX
	cipher.InitKey([]byte(key))

	for i := 0; i < b.N; i++ {
		cipher.encryptCascade(y, iterations)
	}
}

func TestAvalanche(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)
	const iters = 255

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		z := make([]byte, len(x))
		copy(y, x)
		copy(z, x)

		var cipher RCX
		cipher.InitKey(key)

		x[0]--
		cipher.encryptCascade(x, iters)
		cipher.encryptCascade(y, iters)
		cipher.encryptCascade(z, iters)

		if !bytes.Equal(y, z) {
			t.Fatalf("failed to encrypt, round %d with seed %d", i, seed)
		}

		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed deep check, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionRCX(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 32; i++ {
		key := generateRandomBytes(t, false)
		x := generateRandomBytes(t, true)
		y := make([]byte, len(x))
		copy(y, x)

		EncryptInplace(key, y, iterations)
		if bytes.Equal(x, y) {
			t.Fatalf("failed encrypt, round %d with seed %d", i, seed)
		}
		ok := primitives.IsDeepNotEqual(x, y, len(x))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		DecryptInplace(key, y, iterations)
		if !bytes.Equal(x, y) {
			t.Fatalf("failed decrypt, round %d with seed %d\n%x\n%x", i, seed, x, y)
		}
	}
}

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

		arr := make([]byte, 512)
		var rc4 RC4
		rc4.InitKey(key)
		for i := 0; i < 256 * 4; i++ {
			rc4.XorInplace(arr)
		}
		rc4.XorInplace(z)

		EncryptInplace(key, y, 0)
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
