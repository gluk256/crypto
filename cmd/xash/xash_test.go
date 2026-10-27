package main

import (
	"encoding/hex"
	"testing"

	"github.com/gluk256/crypto/crutils"
)

func TestDecryptFile(t *testing.T) {
	expectedHashStr := "2f8586076db2559d3e72a43c4ae8a1f5957abb23ca4a1f46e380dd640536eedb"
	text := "lorem ipsum dolor sit amet"
	hash := crutils.Sha2([]byte(text))
	hashStr := hex.EncodeToString(hash)
	if hashStr != expectedHashStr {
		t.Fatal("Wrong hash")
	}
}
