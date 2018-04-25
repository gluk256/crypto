package primitives

import (
	"bytes"
	"testing"
)

func isEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReverse(t *testing.T) {
	s := []int{1,2,3,4,5,6,7}
	r := []int{7,6,5,4,3,2,1}
	w := []int{1,2,3,4,5,6,7}

	ReverseInt(s)
	if !isEqual(s, r) {
		t.Fatalf("false negative [%v] vs. [%v]", s, r)
	}
	if isEqual(s, w) {
		t.Fatalf("false positive [%v] vs. [%v]", s, w)
	}

	ReverseInt(s)
	if isEqual(s, r) {
		t.Fatalf("false negative [%v] vs. [%v]", s, r)
	}
	if !isEqual(s, w) {
		t.Fatalf("false positive [%v] vs. [%v]", s, w)
	}
}

func TestSubstitute(t *testing.T) {
	var s1 string = "abcdefghijklmnopqrstuvwxyz"
	const s2 string = "0123456789"
	const i = 1
	const next = byte('#')
	var prev byte
	var b []byte

	b = []byte(s1)
	prev = b[i]
	Substitute(b, prev, next)
	if b[i] != next {
		t.Fatal("did not change")
	} else {
		for x, c := range b {
			if c == prev {
				t.Fatalf("char %c still occur at position %d", c, x)
			}
		}
	}

	b = []byte(s2)
	prev = b[i]
	Substitute(b, prev, next)
	if b[i] != next {
		t.Fatal("did not change")
	} else {
		for x, c := range b {
			if c == prev {
				t.Fatalf("char %c still occur at position %d", c, x)
			}
		}
	}
}

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

func TestXorInplace(t *testing.T) {
	sample1 := []byte("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	sample2 := []byte("3d0f32465f276ca3b9b78832e2deaff4ae4c75d09db9ab98bcef68869d65c7e7f0c19807d791d5ffe4f4dcc7700397a590325bf8bf78b3b7bef7af64574e572c")
	gamma := sample1
	src := sample2
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
	ok := IsDeepNotEqual(b1, b2, sz)
	if !ok {
		t.Fatal("xor failed deep check")
	}

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
