package main

import (
	"encoding/hex"
	"testing"

	"github.com/gluk256/crypto/algo/keccak"
)

func TestDecryptFile(t *testing.T) {
	expectedHashStr := "455ac2ec00ed36985aae32868291e9803a589b89f1bc535d7c8b2c474f3804fa"
	text := "lorem ipsum dolor sit amet"
	hash := keccak.Digest([]byte(text), 32)
	hashStr := hex.EncodeToString(hash)
	if hashStr != expectedHashStr {
		t.Fatal("Wrong hash")
	}
}
