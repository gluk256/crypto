package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

func TestDecryptFile(t *testing.T) {
	prefix := string("../../testdata/")

	encyprted, err := os.ReadFile(prefix + "lorem-fox.encr")
	if err != nil {
		t.Fatal("Failed to load data: ", err.Error())
	} else if len(encyprted) == 0 {
		t.Fatal("File is empty")
	}

	lorem, err := os.ReadFile(prefix + "lorem")
	if err != nil {
		t.Fatal("Failed to load data: ", err.Error())
	} else if len(lorem) == 0 {
		t.Fatal("File is empty")
	}

	fox, err := os.ReadFile(prefix + "fox")
	if err != nil {
		t.Fatal("Failed to load data: ", err.Error())
	} else if len(fox) == 0 {
		t.Fatal("File is empty")
	}

	key1 := keccak.Digest([]byte("dsydygbwdhsizsdwltbx"), 256)
	key2 := keccak.Digest([]byte("jaiuaumoekbuwesrsvkr"), 256)

	decr1, spacing, err := crutils.Decrypt(key1, encyprted)
	if err != nil {
		t.Fatal("Failed to decrypt level 1: ", err)
	}

	decr2, _, err := crutils.DecryptStegContentOfUnknownSize(key2, spacing)
	if err != nil {
		t.Fatal("Failed to decrypt level 2: ", err)
	}

	if !bytes.Equal(decr1, lorem) {
		t.Fatal("Failed to decrypt lorem-ipsum")
	}

	if !bytes.Equal(decr2, fox) {
		t.Fatal("Failed to decrypt quick-brown-fox")
	}
}
