package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

func TestDecryptFile(t *testing.T) {
	key := keccak.Digest([]byte("fzmbtpuperlf9egkm9l3"), 256)
	prefix := string("../../testdata/")
	encyprted, err := os.ReadFile(prefix + "quick")
	if err != nil {
		t.Fatal("Failed to load data: ", err.Error())
	} else if len(encyprted) == 0 {
		t.Fatal("Encrypted file is empty")
	}

	lorem, err := os.ReadFile(prefix + "lorem")
	if err != nil {
		t.Fatal("Failed to load data: ", err.Error())
	} else if len(lorem) == 0 {
		t.Fatal("File is empty")
	}

	decr, err := crutils.DecryptQuick(key, encyprted)
	if err != nil {
		t.Fatal("Failed to decrypt level: ", err)
	}
	if !bytes.Equal(decr, lorem) {
		t.Fatal("Failed to decrypt lorem-ipsum")
	}
}
