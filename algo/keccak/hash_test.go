package keccak

import (
	"bytes"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/gluk256/crypto/algo/primitives"
)

var input = []string{
	"",
	"zxcv",
	" The supply of government exceeds the demand by huge margin. ",
	"Ineptocracy - a system of government where the least capable to lead are elected by the least capable to produce, and where the members of society least likely to sustain themselves or succeed, are rewarded with goods and services paid for by the confiscated wealth of a diminishing number of producers.",
	"Of all tyrannies, a tyranny sincerely exercised for the good of its victims may be the most oppressive. It would be better to live under robber barons than under omnipotent moral busybodies. The robber baron's cruelty may sometimes sleep, his cupidity may at some point be satiated; but those who torment us for our own good will torment us without end for they do so with the approval of their own conscience.",
}

var expected = []string{
	"0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
	"e7ff11ec516b91fa7feb61ebf19c89487b78bf49a077824efd08e392549522817b24ca65776341dddd91ce499951bca6bf267d00cf1e81629441e32eb70e2111",
	"1e737292b0b2d00227eb29b851ffd92c00908e44a51ef866fe7a934421b54191bafb86f4b46adf4252d2e6c5f3c7d04954045fdcea04b7d1e5057e94a2e7b1f6",
	"3d0f32465f276ca3b9b78832e2deaff4ae4c75d09db9ab98bcef68869d65c7e7f0c19807d791d5ffe4f4dcc7700397a590325bf8bf78b3b7bef7af64574e572c",
	"0b4726f2c9b79347d1f2340ee2ba35a6d9711dd84d6bcde7907135f0c57f4cedb3205ccb2b436b81510f199e996c3b3601ec2a92456718165c62a43e09ab5c11",
}

const sz = 64

func BenchmarkHash(b *testing.B) {
	buf := make([]byte, sz)
	var k Keccak512
	k.Write([]byte(input[3]))
	for i := 0; i < b.N; i++ {
		k.Read(buf)
	}
}

func TestHash(t *testing.T) {
	exp := make([]byte, sz)
	for i, text := range input {
		hash := Digest([]byte(text), sz)
		hex.Decode(exp, []byte(expected[i]))
		if !bytes.Equal(hash, exp) {
			t.Fatalf("failed test number %d, result: \n[%x]", i, hash)
		}
	}

	res := make([]byte, sz)
	for i := 0; i < len(input); i++ {
		var k Keccak512
		k.Write([]byte(input[i]))
		k.Read(res)
		s := fmt.Sprintf("%x", res)
		if s != expected[i] {
			t.Fatalf("failed advanced test number %d, result: \n[%x]", i, res)
		}
	}
}

func TestEncrypt(t *testing.T) {
	const sz = 1024 * 16
	key := []byte(input[4])
	b1 := Digest([]byte(expected[0]), sz)
	b2 := Digest([]byte(expected[0]), sz)
	xx := Digest([]byte(expected[0]), sz)
	if !bytes.Equal(b1, b2) || !bytes.Equal(b1, xx) {
		t.Fatal("copy failed")
	}

	gamma := Digest(key, len(b1))
	digestXor(key, b1)
	if bytes.Equal(b1, xx) {
		t.Fatal("xor failed")
	}
	ok := primitives.IsDeepNotEqual(b1, xx, sz)
	if !ok {
		t.Fatal("xor failed deep check")
	}

	digestXor(key, b2)
	if bytes.Equal(b2, xx) {
		t.Fatal("xor failed second")
	}
	ok = primitives.IsDeepNotEqual(b2, xx, sz)
	if !ok {
		t.Fatal("xor failed second check")
	}

	primitives.XorInplace(b2, gamma, sz)
	if !bytes.Equal(xx, b2) {
		t.Fatal("b2 did not return to previous state")
	}

	digestXor(key, b1)
	if !bytes.Equal(b1, xx) {
		t.Fatal("b1 did not return to previous state")
	}
}

func digestXor(in []byte, out []byte) {
	var d Keccak512
	d.Write(in)
	d.ReadXor(out)
}

func TestReadXor(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 1024; i++ {
		key := generateRandomBytes(t)
		x := generateRandomBytes(t)
		y := make([]byte, len(x))
		z := make([]byte, len(x))
		gamma := make([]byte, len(y))
		copy(y, x)

		var k1, k2, k3 Keccak512
		k1.Write(key)
		k2.Write(key)
		k3.Write(key)

		k2.ReadXor(x)
		k1.Read(gamma)
		k3.ReadXor(z)

		if !bytes.Equal(z, gamma) {
			t.Fatalf("failed round %d with seed %d", i, seed)
		}

		primitives.XorInplace(y, gamma, len(y))
		if !bytes.Equal(x, y) {
			t.Fatalf("failed round %d with seed %d", i, seed)
		}
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

func TestXorIn(t *testing.T) {
	sample := [8]byte{0xed, 0x01, 0xd4, 0x0a, 0xb7, 0x80, 0x15, 0xcf}
	const expected = uint64(0xcf1580b70ad401ed)

	var k Keccak512
	var b []byte
	for i := 0; i < Rate/8; i++ {
		b = append(b, sample[:]...)
	}
	if len(b) != Rate {
		t.Fatal("wrong buf len")
	}
	for i := 0; i < Rate; i++ {
		b[i] += byte(i / 8)
	}
	k.absorb(b)
	exp := expected
	for i := 0; i < Rate/8; i++ {
		if k.a[i] != exp {
			t.Fatalf("a[%d] != expected [%x != %x]", i, k.a[i], exp)
		}
		exp += 0x0101010101010101
	}
	for i := Rate / 8; i < 25; i++ {
		if k.a[i] != 0 {
			t.Fatalf("a[%d] != 0", i)
		}
	}
}
