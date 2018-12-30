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

		encyprted := EncryptLevelTwo(key, data, true)
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}
		if len(encyprted) != len(orig) * 2 {
			t.Fatalf("len(encyprted) failed [%d vs. %d]", len(encyprted), len(orig) * 2)
		}

		d2 := make([]byte, len(encyprted))
		copy(d2, encyprted)
		d2[sz/2]++ // change at least one bit
		d2 = EncryptLevelTwo(key, d2, false)
		ok = primitives.IsDeepNotEqual(d2, orig, len(orig))
		if !ok {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted := EncryptLevelTwo(key, encyprted, false)
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

		encyprted, err := EncryptLevelThree(key, data, true)
		if err != nil {
			t.Fatal(err)
		}
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}
		if len(encyprted) - sz != SaltSize + AesEncryptedSizeDiff {
			t.Fatalf("size diff failed [%d vs. %d]", len(encyprted) - sz, SaltSize + AesSaltSize)
		}

		d2 := make([]byte, len(encyprted))
		copy(d2, encyprted)
		d2[sz/2]++ // change at least one bit
		d2, err = EncryptLevelThree(key, d2, false)
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
		if len(encyprted) != sz * 2 + SaltSize + AesEncryptedSizeDiff {
			t.Fatalf("len(encyprted) failed [%d vs. %d]", len(encyprted), sz * 2 + SaltSize + AesEncryptedSizeDiff)
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
		paddedSize := primitives.FindNextPowerOfTwo(sz + 4)
		if len(encyprted) != paddedSize * 2 + SaltSize + AesEncryptedSizeDiff {
			t.Fatalf("len(encyprted) failed [%d vs. %d]", len(encyprted), sz * 2 + SaltSize + AesEncryptedSizeDiff)
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

	multiplier := 1
	for i := 0; i < 8; i++ {
		keysz := (mrand.Int() % 64) + 13
		key := generateRandomBytes(t)
		key = key[:keysz]
		keySteg := generateRandomBytes(t)
		keySteg = keySteg[:keysz]

		steg := generateRandomBytes(t)
		origSteg := make([]byte, len(steg))
		copy(origSteg, steg)

		encyprtedSteg, err := EncryptLevelFive(keySteg, steg, true)
		if err != nil {
			t.Fatalf("Error encrypting l.5: %s", err.Error())
		}
		origEncryptedSteg := make([]byte, len(encyprtedSteg))
		copy(origEncryptedSteg, encyprtedSteg)

		data := generateRandomBytesMinSize(t, len(encyprtedSteg) * multiplier + 37)
		origData := make([]byte, len(data))
		copy(origData, data)

		encyprted, err := EncryptSteg(key, data, encyprtedSteg)
		if err != nil {
			t.Fatalf("EncryptSteg error: %s", err.Error())
		}

		decryptedData, raw, err := DecryptSteg(key, encyprted)
		if err != nil {
			t.Fatalf("DecryptSteg error: %s", err.Error())
		}
		if !bytes.Equal(decryptedData, origData) {
			t.Fatalf("failed to decrypt data, round %d with seed %d", i, seed)
		}
		if !bytes.Equal(raw[:len(origEncryptedSteg)], origEncryptedSteg) {
			t.Fatalf("failed to decrypt raw steg, round %d with seed %d", i, seed)
		}

		decryptedSteg, err := DecryptStegContentOfUnknownSize(keySteg, raw)
		if err != nil {
			t.Fatalf("DecryptStegContentOfUnknownSize error: %s", err.Error())
		}
		if !bytes.Equal(decryptedSteg, origSteg) {
			t.Fatalf("decrypted produced wrong result, round %d with seed %d", i, seed)
		}

		multiplier *= 2
		if multiplier == 0 {
			multiplier = 1
		}
	}
}
