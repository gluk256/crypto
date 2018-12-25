package crutils

import (
	"time"
	"bytes"
	"testing"
	mrand "math/rand"

	"github.com/gluk256/crypto/algo/primitives"
)

func TestAes(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 256; i++ {
		key := generateRandomBytes(t)
		key = key[:32]
		salt := generateRandomBytes(t)
		salt = salt[:12]
		data := generateRandomBytes(t)
		sz := len(data)
		expected := make([]byte, sz)
		copy(expected, data)

		encrypted, err := EncryptAES(key, salt, data)
		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}

		diff := len(encrypted) - len(expected)
		if diff != 16 {
			t.Fatalf("weird diff: %d", diff)
		}

		ok := primitives.IsDeepNotEqual(encrypted, data, len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		decrypted, err := DecryptAES(key, salt, encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %s", err)
		}

		if !bytes.Equal(decrypted, expected) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}

		decrypted2, err := DecryptAES(key, salt, encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %s", err)
		}

		if !bytes.Equal(decrypted2, expected) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}

		encrypted[sz/2]++
		for i := 0; i < sz - 16; i++ {
			encrypted[i] = byte(i)
		}

		_, err = DecryptAES(key, salt, encrypted)
		if err == nil {
			t.Fatalf("decryption false positive, despite changing byte %d", sz/2)
		}

		encrypted[sz/2]--
		encrypted[sz-1]++
		_, err = DecryptAES(key, salt, encrypted)
		if err == nil {
			t.Fatal("decryption false positive, despite changing the MAC")
		}
	}
}

func TestEncryptionLevelZero(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 256; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		EncryptInplaceLevelZero(key, data)
		ok := primitives.IsDeepNotEqual(orig, data, len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		EncryptInplaceLevelZero(key, data) // decrypt
		if !bytes.Equal(data, orig) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionLevelOne(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 256; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		EncryptInplaceLevelOne(key, data, true)
		ok := primitives.IsDeepNotEqual(orig, data, len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		d2 := make([]byte, sz)
		copy(d2, data)
		d2[sz/2]++ // change at least one bit
		EncryptInplaceLevelOne(key, d2, false) // decrypt
		EncryptInplaceLevelOne(key, data, false) // decrypt

		if !bytes.Equal(data, orig) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}

		ok = primitives.IsDeepNotEqual(data, d2, sz)
		if !ok {
			t.Fatalf("decryption false positive, despite changing byte %d, round %d with seed %d", sz/2, i, seed)
		}
	}
}
