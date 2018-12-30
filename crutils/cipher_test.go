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

	for i := 0; i < 64; i++ {
		key := generateRandomBytes(t)
		key = key[:AesKeySize]
		salt := generateRandomBytes(t)
		salt = salt[:AesSaltSize]
		data := generateRandomBytes(t)
		sz := len(data)
		expected := make([]byte, sz)
		copy(expected, data)

		encrypted, err := EncryptAES(key, salt, data)
		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}

		diff := len(encrypted) - len(expected)
		if diff != AesEncryptedSizeDiff {
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

		encrypted[sz/2]++ // change at least one bit
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

	for i := 0; i < 16; i++ {
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

	for i := 0; i < 16; i++ {
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

func TestEncryptionLevelTwo(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 16; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		encyprted, err := EncryptLevelThree(key, data, true)
		if err != nil {
			t.Fatal(err)
		}
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}
		if len(encyprted) - len(orig) != SaltSize + AesEncryptedSizeDiff {
			t.Fatalf("size diff failed [%d vs. %d]", len(encyprted) - len(orig), SaltSize + AesSaltSize)
		}

		d2 := make([]byte, len(encyprted))
		copy(d2, encyprted)
		d2[sz/2]++ // change at least one bit
		_, err = EncryptLevelThree(key, d2, false)
		if err == nil {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted, err := EncryptLevelThree(key, encyprted, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionLevelThree(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 16; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		encyprted := EncryptLevelTwo(key, data, true)
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		decrypted := EncryptLevelTwo(key, encyprted, false)
		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionLevelFour(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 16; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		encyprted, err := EncryptLevelFour(key, data, true)
		if err != nil {
			t.Fatal(err)
		}
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		d2 := make([]byte, len(encyprted))
		copy(d2, encyprted)
		d2[sz/2]++ // change at least one bit
		_, err = EncryptLevelFour(key, d2, false)
		if err == nil {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted, err := EncryptLevelFour(key, encyprted, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionLevelFive(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 16; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		encyprted, err := EncryptLevelFive(key, data, true)
		if err != nil {
			t.Fatal(err)
		}
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		d2 := make([]byte, len(encyprted))
		copy(d2, encyprted)
		d2[sz/2]++ // change at least one bit
		_, err = EncryptLevelFive(key, d2, false)
		if err == nil {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted, err := EncryptLevelFive(key, encyprted, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(decrypted) > len(orig) {
			if !bytes.Equal(decrypted[:len(orig)], orig) {
				t.Fatalf("decrypted != expected, [%d %d] round %d with seed %d", len(orig), len(decrypted), i, seed)
			}
		}
		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decrypted != expected, [%d %d] round %d with seed %d", len(orig), len(decrypted), i, seed)
		}
	}
}

func TestEncryptionSteg(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 4; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		steg := generateRandomBytes(t)
		if len(data) > len(steg) {
			data = data[:len(steg)]
		} else {
			steg = steg[:len(data)]
		}
		sz := len(data)
		origData := make([]byte, sz)
		origSteg := make([]byte, sz)
		copy(origData, data)
		copy(origSteg, steg)

		encyprted, err := EncryptSteg(key, data, steg)
		if err != nil {
			t.Fatal(err)
		}

		decryptedData, decryptedSteg, err := DecryptSteg(key, encyprted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedData, origData) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
		if !bytes.Equal(decryptedSteg, origSteg) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionCompatibility(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 4; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t)
		key = key[:keysz]
		data := generateRandomBytes(t)
		sz := len(data)
		origData := make([]byte, sz)
		copy(origData, data)

		encyprted, err := EncryptLevelFour(key, data, true)
		if err != nil {
			t.Fatal(err)
		}

		decryptedData, _, err := DecryptSteg(key, encyprted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedData, origData) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}

	// todo: vice versa [EncryptSteg + DecryptLevelFour]
	// todo: switch to v.5
}

