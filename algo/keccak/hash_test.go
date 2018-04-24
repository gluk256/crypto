package keccak

import (
	"testing"
	"bytes"
	"encoding/hex"
	mrand "math/rand"
	"time"
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

func TestMin(t *testing.T) {
	x1 := Min(777, 778)
	x2 := Min(555, 554)
	x3 := Min(0, 1)
	x4 := Min(-1, 0)
	x5 := Min(777, 777)
	x6 := Min(-1, -11)
	x7 := Min(1, -11)
	if x1 != 777 || x2 != 554 || x3 != 0 || x4 != -1 || x5 != 777 || x6 != -11 || x7 != -11 {
		t.Fatal("failed")
	}
}

func TestHash(t *testing.T) {
	exp := make([]byte, sz)
	for i, text := range input {
		hash := digest([]byte(text), sz)
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
		hex.Decode(exp, []byte(expected[i]))
		if !bytes.Equal(res, exp) {
			t.Fatalf("failed advanced test number %d, result: \n[%x]", i, res)
		}
	}
}

func BenchmarkHash(b *testing.B) {
	buf := make([]byte, sz)
	var k Keccak512
	k.Write([]byte(input[3]))
	for i := 0; i < b.N; i++ {
		k.Read(buf)
	}
}

func TestXorInplace(t *testing.T) {
	gamma := []byte(expected[4])
	src := []byte(expected[3])
	sz := len(src)
	b1 := make([]byte, sz)
	b2 := make([]byte, sz)
	copy(b1, src)
	copy(b2, src)
	if !bytes.Equal(b1, b2) || !bytes.Equal(b1, src) {
		t.Fatal("copy failed")
	}

	XorInplace(b1, gamma, sz)
	if bytes.Equal(b1, b2) {
		t.Fatal("xor failed")
	}
	checkDeepNotEqual(t, b1, b2, sz)

	XorInplace(b1, gamma, sz)
	if !bytes.Equal(b1, b2) {
		t.Fatal("decrypt failed")
	}

	XorInplace(b1, b1, sz)
	zero := make([]byte, sz)
	if !bytes.Equal(b1, zero) {
		t.Fatal("self-destruction failed")
	}
}

func TestEncrypt(t *testing.T) {
	const sz = 1024 * 16
	key := []byte(input[4])
	b1 := digest([]byte(expected[0]), sz)
	b2 := digest([]byte(expected[0]), sz)
	xx := digest([]byte(expected[0]), sz)
	if !bytes.Equal(b1, b2) || !bytes.Equal(b1, xx) {
		t.Fatal("copy failed")
	}

	gamma := digest(key, len(b1))
	digestXor(key, b1)
	if bytes.Equal(b1, xx) {
		t.Fatal("xor failed")
	}
	checkDeepNotEqual(t, b1, xx, sz)

	digestXor(key, b2)
	if bytes.Equal(b2, xx) {
		t.Fatal("xor failed")
	}
	checkDeepNotEqual(t, b2, xx, sz)

	XorInplace(b2, gamma, sz)
	if !bytes.Equal(xx, b2) {
		t.Fatal("b2 did not return to previous state")
	}

	digestXor(key, b1)
	if !bytes.Equal(b1, xx) {
		t.Fatal("b1 did not return to previous state")
	}
}

func checkDeepNotEqual(t *testing.T, a []byte, b []byte, sz int) {
	const block = 4
	for i := 0; i < sz - block; i += 2 {
		checkBlockNotEqual(t, a, b, i, block)
	}
}

func checkBlockNotEqual(t *testing.T, a []byte, b []byte, off int, block int) {
	for i := off; i < off + block; i++ {
		if a[i] != b[i] {
			return
		}
	}
	t.Fatalf("checkDeepNotEqual failed, offset = %d", off)
}

func digest(in []byte, sz int) []byte {
	var d Keccak512
	d.Write(in)
	out := make([]byte, sz)
	d.Read(out)
	return out
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
		y := cloneBytes(x)

		var k1, k2 Keccak512
		k1.Write(key)
		k2.Write(key)
		k2.ReadXor(x)

		gamma := make([]byte, len(y))
		k1.Read(gamma)
		XorInplace(y, gamma, len(y))

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
		t.Fatal("failed to generate randon bytes")
	}
	return b
}

func cloneBytes(src []byte) []byte {
	b := make([]byte, len(src))
	copy(b, src)
	return b
}
