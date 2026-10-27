package main

import (
	"bytes"
	"os"
	"testing"
)

func TestDecryptFile(t *testing.T) {
	key := []byte("fxmbtpuperlf9egkm9l3")
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

	decr, _, err := tryAllKeys("", key, encyprted, true, false)
	if err != nil {
		t.Fatal("Failed to decrypt level: ", err)
	}
	if !bytes.Equal(decr, lorem) {
		t.Fatal("Failed to decrypt lorem-ipsum")
	}
}
