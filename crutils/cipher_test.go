package crutils

import (
	"time"
	"bytes"
	"testing"
	mrand "math/rand"

	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/algo/rcx"
)

func TestPadding(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	var b, s, zero []byte
	zero = make([]byte, 1024*8)
	b = generateRandomBytes(t)
	b = addSpacing(b)
	b, s = splitSpacing(b)
	ok := primitives.IsDeepNotEqual(s, zero, len(s))
	if !ok {
		t.Fatalf("spacing failed with seed %d", seed)
	}

	sz := len(b)
	p, err := addPadding(b, 1024, false)
	if err != nil {
		t.Fatalf("weird error with seed %d", seed)
	}
	ok = primitives.IsDeepNotEqual(p[sz:1024], zero, 1024-sz)
	if !ok {
		t.Fatalf("padding failed with seed %d", seed)
	}
}

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

		EncryptInplaceLevelOne(key, data, true, false)
		ok := primitives.IsDeepNotEqual(orig, data, len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}

		d2 := make([]byte, sz)
		copy(d2, data)
		d2[sz/2]++ // change at least one bit
		EncryptInplaceLevelOne(key, d2, false, false) // decrypt
		EncryptInplaceLevelOne(key, data, false, false) // decrypt

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

		encyprted := EncryptLevelTwo(key, data, true, false)
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
		d2 = EncryptLevelTwo(key, d2, false, false)
		ok = primitives.IsDeepNotEqual(d2, orig, len(orig))
		if !ok {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted := EncryptLevelTwo(key, encyprted, false, false)
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

		encyprted, err := EncryptInplaceLevelThree(key, data, true)
		if err != nil {
			t.Fatal(err)
		}
		ok := primitives.IsDeepNotEqual(orig, encyprted[16:], len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}
		if len(encyprted) != len(orig) + EncryptedSizeDiff {
			t.Fatalf("len(encyprted) failed [%d vs. %d]", len(encyprted), len(orig) + EncryptedSizeDiff)
		}

		d2 := make([]byte, len(encyprted))
		copy(d2, encyprted)
		d2[sz/2]++ // change at least one bit
		d2, err = EncryptInplaceLevelThree(key, d2, false)
		if err == nil {
			t.Fatal("false positive")
		}

		decrypted, err := EncryptInplaceLevelThree(key, encyprted, false)
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

		encyprted, err := EncryptLevelFour(key, data, true, false)
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
		d2, err = EncryptLevelFour(key, d2, false, false)
		if err == nil {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted, err := EncryptLevelFour(key, encyprted, false, false)
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

		encyprted, err := EncryptLevelFive(key, data, true, false)
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
		_, err = EncryptLevelFive(key, d2, false, false)
		if err == nil {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted, err := EncryptLevelFive(key, encyprted, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}
	}
}

func TestEncryptionLevelSix(t *testing.T) {
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

		encyprted, err := EncryptLevelSix(key, data, true, false)
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
		_, err = EncryptLevelSix(key, d2, false, false)
		if err == nil {
			t.Fatal("decrypted fake data: false positive")
		}

		decrypted, err := EncryptLevelSix(key, encyprted, false, false)
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

		encyprtedSteg, err := EncryptLevelSix(keySteg, steg, true, false)
		if err != nil {
			t.Fatalf("Error encrypting l.5: %s", err.Error())
		}
		origEncryptedSteg := make([]byte, len(encyprtedSteg))
		copy(origEncryptedSteg, encyprtedSteg)

		data := generateRandomBytesMinSize(t, len(encyprtedSteg) * multiplier + 37)
		origData := make([]byte, len(data))
		copy(origData, data)

		encryprted, err := EncryptSteg(key, data, encyprtedSteg, false)
		if err != nil {
			t.Fatalf("EncryptSteg error: %s", err.Error())
		}

		decryptedData, raw, err := DecryptSteg(key, encryprted, false)
		if err != nil {
			t.Fatalf("DecryptSteg error: %s", err.Error())
		}
		if !bytes.Equal(decryptedData, origData) {
			t.Fatalf("failed to decrypt data, round %d with seed %d", i, seed)
		}
		if !bytes.Equal(raw[:len(origEncryptedSteg)], origEncryptedSteg) {
			t.Fatalf("failed to decrypt raw steg, round %d with seed %d", i, seed)
		}

		decryptedSteg, err := DecryptStegContentOfUnknownSize(keySteg, raw, false)
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

func TestStegSize(t *testing.T) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	data := make([]byte, 124)
	steg := make([]byte, len(data))
	encryprted, err := EncryptSteg(key, data, steg, false)
	if err != nil {
		t.Fatalf("EncryptSteg error: %s", err.Error())
	}
	const expected = 128 * 2 + EncryptedSizeDiff
	if len(encryprted) != expected {
		t.Fatalf("Wrong len(encrypted): %d vs. %d", len(encryprted), expected)
	}
}

func BenchmarkKeccak(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptInplaceKeccak(key, data)
	}
}

func BenchmarkRCX(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		rcx.EncryptInplaceRCX(key, d, RcxIterationsDefault, true)
	}
}

func BenchmarkL0(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptInplaceLevelZero(key, data)
	}
}

func BenchmarkL1(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptInplaceLevelOne(key, data, true, false)
	}
}

func BenchmarkL1quick(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptInplaceLevelOne(key, data, true, true)
	}
}

func BenchmarkL2(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptLevelTwo(key, data, true, false)
	}
}

func BenchmarkL2quick(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptLevelTwo(key, data, true, true)
	}
}

func BenchmarkL3(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptInplaceLevelThree(key, data, true)
		if err != nil {
			b.Fatalf("Benchmark L3 error: %s", err.Error())
		}
	}
}

func BenchmarkL4(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptLevelFour(key, data, true, false)
		if err != nil {
			b.Fatalf("Benchmark L4 error: %s", err.Error())
		}
	}
}

func BenchmarkL4quick(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptLevelFour(key, data, true, true)
		if err != nil {
			b.Fatalf("Benchmark L4 error: %s", err.Error())
		}
	}
}

func BenchmarkL5(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptLevelFive(key, data, true, false)
		if err != nil {
			b.Fatalf("Benchmark L5 error: %s", err.Error())
		}
	}
}

func BenchmarkL5quick(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptLevelFive(key, data, true, true)
		if err != nil {
			b.Fatalf("Benchmark L5 error: %s", err.Error())
		}
	}
}

func BenchmarkL6(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptLevelSix(key, data, true, false)
		if err != nil {
			b.Fatalf("Benchmark L6 error: %s", err.Error())
		}
	}
}

func BenchmarkL6quick(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := EncryptLevelSix(key, data, true, true)
		if err != nil {
			b.Fatalf("Benchmark L6 error: %s", err.Error())
		}
	}
}

func BenchmarkSteg(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	steg := make([]byte, len(data))

	for i := 0; i < b.N; i++ {
		_, err := EncryptSteg(key, data, steg, false)
		if err != nil {
			b.Fatalf("EncryptSteg error: %s", err.Error())
		}
	}
}

func BenchmarkStegQuick(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	steg := make([]byte, len(data))

	for i := 0; i < b.N; i++ {
		_, err := EncryptSteg(key, data, steg, true)
		if err != nil {
			b.Fatalf("EncryptSteg error: %s", err.Error())
		}
	}
}

func BenchmarkStegQuickBigData(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 100000000) // 100 Mb
	steg := make([]byte, len(data))

	for i := 0; i < b.N; i++ {
		_, err := EncryptSteg(key, data, steg, true)
		if err != nil {
			b.Fatalf("EncryptSteg error: %s", err.Error())
		}
	}
}
