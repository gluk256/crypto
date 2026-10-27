package main

import (
	"os"
	"testing"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

func TestDecryptFile(t *testing.T) {
	// this test decrypts 4 levels of a single file
	var err error
	var key, encryprted, decr, spacing []byte
	passwords := []string{"level1", "level2", "level3", "level4"}
	results := []string{"Lorem ipsum dolor sit amet", "The quick brown fox", "xxxxxxxxxxx", "zxcvbnm"}
	prefix := string("../../testdata/")
	encryprted, err = os.ReadFile(prefix + "x4")
	if err != nil {
		t.Fatal("Failed to load data: ", err.Error())
	} else if len(encryprted) == 0 {
		t.Fatal("File is empty")
	}

	for i, pass := range passwords {
		key = keccak.Digest([]byte(pass), 256)
		if 0 == i {
			decr, spacing, err = crutils.Decrypt(key, encryprted)
		} else {
			decr, spacing, err = crutils.DecryptStegContentOfUnknownSize(key, encryprted)
		}
		encryprted = spacing
		if err != nil {
			t.Fatalf("Failed to decrypt level %d: %s", i+1, err)
		}
		if !isEqual(decr, results[i]) {
			t.Fatalf("Level %d decryption wrong result (expected: [%s])", i+1, results[i])
		}
	}
}

func isEqual(a []byte, s string) bool {
	b := []byte(s)
	lim := len(b)
	if lim > len(a) {
		lim = len(a)
	}
	for i := 0; i < lim; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
