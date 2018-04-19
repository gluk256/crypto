package crutils

import (
	"testing"
	"bytes"
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

func TestRand(t *testing.T) {
	const sz = 1024
	b1 := make([]byte, sz)
	b2 := make([]byte, sz)
	b3 := make([]byte, sz)
	Rand(b1, sz)
	copy(b2, b1)
	copy(b3, b1)
	if !bytes.Equal(b1, b2) || !bytes.Equal(b1, b3) {
		t.Fatal("copy failed")
	}
	RandXor(b1, sz)
	if bytes.Equal(b1, b3) {
		t.Fatal("RandXor failed")
	}
	Rand(b2, sz)
	if bytes.Equal(b2, b3) {
		t.Fatal("Rand failed")
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
