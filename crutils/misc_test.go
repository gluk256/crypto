package crutils

import (
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

	Reverse(s)

	if !isEqual(s, r) {
		t.Fatalf("false negative [%v] vs. [%v]", s, r)
	}
	if isEqual(s, w) {
		t.Fatalf("false positive [%v] vs. [%v]", s, w)
	}
}