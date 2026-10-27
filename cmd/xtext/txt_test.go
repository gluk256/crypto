package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

func TestDecryptFile(t *testing.T) {
	// this test decrypts pre-encrypted text
	var err error
	var encryptedStrong, keyStrong, encryptedWeak, keyWeak, expected, decryptedS, decryptedW, encrypted []byte
	encryptedStrong = []byte("deff5a51ec4d31caff7202ea2b536d9d14009785d97e50488d541c0547a1d40152e5d0b3c1648e851cdcbd6a7fd1d7d9a049d40400a09c4831a21a39514b9267ecfd90a767b3664c5df27bc87ed280768195201f96c03f80722b957046608c97538c86bc2374e2aab447428bc7a80799ee591e055fda7941ecb2b584fb4172453d146ad3b0e029f5a938bfa30956a1a5fe143f6a4b7517ce1d2ed13454d7a2bad88062beff1c1758ce374566a42785e9cde198c71bf38cf9eea4a15204afba52")
	keyStrong = []byte("zoydhg3td75pkkogoh41")
	encryptedWeak = []byte("1e95125738a89f7480ba8cb535dce8ee2e83924f4653e4d544ea")
	keyWeak = []byte("5qeuehs986ee8cya9kj0")
	expected = []byte("lorem ipsum dolor sit amet")

	encrypted = make([]byte, len(encryptedStrong)/2)
	hex.Decode(encrypted, encryptedStrong)
	decryptedS, _, err = crutils.Decrypt(keccak.Digest(keyStrong, 256), encrypted)
	if err != nil {
		t.Fatal("Strong encryption failed: ", err)
	}
	if !bytes.Equal(decryptedS, expected) {
		t.Fatal("Strong encryption produced unexpected result")
	}

	encrypted = encrypted[:len(encryptedWeak)/2]
	hex.Decode(encrypted, encryptedWeak)
	keyWeak = keccak.Digest(keyWeak, 256)
	crutils.EncryptInplaceKeccak(keyWeak, encrypted)
	crutils.DecryptInplaceRCX(keyWeak, encrypted)
	decryptedW = encrypted // data ecrypted/decrypted inplace

	if !bytes.Equal(decryptedW, expected) {
		t.Fatal("Weak encryption produced unexpected result")
	}
}
