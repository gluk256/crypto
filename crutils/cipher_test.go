package crutils

import (
	"bytes"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/algo/rcx"
)

func TestKeyholder(t *testing.T) {
	const expected = 1536
	sz := getKeyHolderSize()
	key := make([]byte, expected)
	if sz != expected {
		t.Fatalf("wrong size [%d vs. %d]", sz, expected)
	}

	k1 := getKey1(key)
	k2 := getKey2(key)
	r := getRcxKey(key)
	a := getAesKey(key)
	s := getAesSalt(key)

	if &k1[0] != &key[256] {
		t.Fatal("key generation failed")
	}

	if &k2[0] != &key[512] {
		t.Fatal("key generation failed")
	}

	if &r[0] != &key[768] {
		t.Fatal("key generation failed")
	}

	if &a[0] != &key[1024] {
		t.Fatal("key generation failed")
	}

	if &s[0] != &key[1280] {
		t.Fatal("key generation failed")
	}
}

func TestPadding(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	var b, s, r, zero []byte
	zero = make([]byte, 1024*8)
	b = generateRandomBytes(t, false)
	r = make([]byte, len(b))
	Randomize(r)
	b = addSpacing(b, r)
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

	for i := 0; i < 16; i++ {
		key := generateRandomBytes(t, false)
		key = key[:AesKeySize]
		salt := generateRandomBytes(t, false)
		salt = salt[:AesSaltSize]
		data := generateRandomBytes(t, true)
		sz := len(data)
		expected := make([]byte, sz)
		copy(expected, data)

		encrypted, err := EncryptAES(key, salt, data)
		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}

		encrypted2 := make([]byte, len(encrypted))
		encrypted3 := make([]byte, len(encrypted))
		encrypted4 := make([]byte, len(encrypted))
		copy(encrypted2, encrypted)
		copy(encrypted3, encrypted)
		copy(encrypted4, encrypted)

		diff := len(encrypted) - len(expected)
		if diff != AesEncryptedSizeDiff {
			t.Fatalf("weird diff: %d", diff)
		}

		ok := primitives.IsDeepNotEqual(encrypted, data, len(data))
		if !ok {
			t.Fatal("deep non-equal test failed")
		}
		ok = primitives.IsDeepNotEqual(encrypted[AesEncryptedSizeDiff:], data, len(data))
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

		decrypted2, err := DecryptAES(key, salt, encrypted2)
		if err != nil {
			t.Fatalf("decryption failed: %s", err)
		}

		if !bytes.Equal(decrypted2, expected) {
			t.Fatalf("decrypted != expected, round %d with seed %d", i, seed)
		}

		encrypted3[sz/2]++ // change at least one bit
		_, err = DecryptAES(key, salt, encrypted3)
		if err == nil {
			t.Fatalf("decryption false positive, despite changing byte %d", sz/2)
		}

		encrypted4[sz-1]++
		_, err = DecryptAES(key, salt, encrypted4)
		if err == nil {
			t.Fatal("decryption false positive, despite changing the MAC")
		}
	}
}

func TestEncryptionQuick(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	for i := 0; i < 3; i++ {
		keysz := (mrand.Int() % 64) + 7
		key := generateRandomBytes(t, false)
		key = key[:keysz]
		data := generateRandomBytes(t, true)
		sz := len(data)
		orig := make([]byte, sz)
		copy(orig, data)

		encyprted, err := EncryptQuick(key, data)
		if err != nil {
			t.Fatal(err)
		}
		if !primitives.IsDeepNotEqual(orig, encyprted, len(data)) {
			t.Fatal("deep non-equal test failed")
		}

		decrypted, err := DecryptQuick(key, encyprted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decrypted != expected, [%d %d] round %d with seed %d", len(orig), len(decrypted), i, seed)
		}
	}
}

func TestEncryptionMain(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	keysz := (mrand.Int() % 64) + 7
	key := generateRandomBytes(t, false)
	key = key[:keysz]
	data := generateRandomBytes(t, true)
	sz := len(data)
	orig := make([]byte, sz)
	copy(orig, data)

	encyprted, err := Encrypt(key, data)
	if err != nil {
		t.Fatal(err)
	}
	ok := primitives.IsDeepNotEqual(orig, encyprted, len(data))
	if !ok {
		t.Fatal("deep non-equal test failed")
	}
	paddedSize := primitives.FindNextPowerOfTwo(sz + 4)
	if len(encyprted) != paddedSize*2+SaltSize+AesEncryptedSizeDiff {
		t.Fatalf("len(encyprted) failed [%d vs. %d]", len(encyprted), sz*2+SaltSize+AesEncryptedSizeDiff)
	}

	d2 := make([]byte, len(encyprted))
	copy(d2, encyprted)
	d2[sz/2]++ // change at least one bit
	_, _, err = Decrypt(key, d2)
	if err == nil {
		t.Fatal("decrypted fake data: false positive")
	}

	decrypted, _, err := Decrypt(key, encyprted)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) > len(orig) {
		if !bytes.Equal(decrypted[:len(orig)], orig) {
			t.Fatalf("decrypted != expected, [%d %d], with seed %d", len(orig), len(decrypted), seed)
		}
	}
	if !bytes.Equal(decrypted, orig) {
		t.Fatalf("decrypted != expected, [%d %d], with seed %d", len(orig), len(decrypted), seed)
	}
}

func TestEncryptionSteg(t *testing.T) {
	seed := time.Now().Unix()
	mrand.Seed(seed)

	keysz := (mrand.Int() % 64) + 13
	key := generateRandomBytes(t, false)
	key = key[:keysz]
	keySteg := generateRandomBytes(t, false)
	keySteg = keySteg[:keysz]

	steg := generateRandomBytes(t, true)
	origSteg := make([]byte, len(steg))
	copy(origSteg, steg)

	encyprtedSteg, err := Encrypt(keySteg, steg)
	if err != nil {
		t.Fatalf("Error encrypting l.5: %s", err.Error())
	}
	origEncryptedSteg := make([]byte, len(encyprtedSteg))
	copy(origEncryptedSteg, encyprtedSteg)

	data := generateRandomBytesMinSize(t, len(encyprtedSteg)+37)
	origData := make([]byte, len(data))
	copy(origData, data)

	encryprted, err := EncryptSteg(key, data, encyprtedSteg)
	if err != nil {
		t.Fatalf("EncryptSteg error: %s", err.Error())
	}

	decryptedData, raw, err := Decrypt(key, encryprted)
	if err != nil {
		t.Fatalf("DecryptSteg error: %s", err.Error())
	}
	if !bytes.Equal(decryptedData, origData) {
		t.Fatalf("failed to decrypt data, with seed %d", seed)
	}
	if !bytes.Equal(raw[:len(origEncryptedSteg)-1], origEncryptedSteg[:len(origEncryptedSteg)-1]) {
		t.Fatalf("failed to decrypt raw steg, with seed %d", seed)
	}

	decryptedSteg, _, err := DecryptStegContentOfUnknownSize(keySteg, raw)
	if err != nil {
		t.Fatalf("DecryptStegContentOfUnknownSize error: %s", err.Error())
	}
	if !bytes.Equal(decryptedSteg, origSteg) {
		t.Fatalf("decrypted produced wrong result, with seed %d", seed)
	}
}

func TestStegSize(t *testing.T) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	data := make([]byte, 124)
	steg := make([]byte, len(data))
	encryprted, err := EncryptSteg(key, data, steg)
	if err != nil {
		t.Fatalf("EncryptSteg error: %s", err.Error())
	}
	const expected = 128*2 + EncryptedSizeDiff
	if len(encryprted) != expected {
		t.Fatalf("Wrong len(encrypted): %d vs. %d", len(encryprted), expected)
	}
}

// 0.015 sec/Mb
func BenchmarkKeccak(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		EncryptInplaceKeccak(key, data)
	}
}

// 0.001 sec/Mb
func BenchmarkAES(b *testing.B) {
	const sz = 1000000
	key := []byte("7eab42de4c3ceb9235fc91acffe746b2")
	salt := key[:AesSaltSize]
	d := make([]byte, sz)
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptAES(key, salt, d)
		if err != nil {
			b.Fatal(err.Error())
		}
		if len(encrypted)-sz != AesEncryptedSizeDiff {
			b.Fatalf("unexpected size diff: %d", len(encrypted)-sz)
		}
	}
}

// 0.006 sec/Mb
func BenchmarkRc4(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		rcx.EncryptInplaceRC4(key, d)
	}
}

// 0.6 sec/Mb
func BenchmarkRcx(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		rcx.EncryptInplaceRcx(key, d, 512)
	}
}

// 0.06 sec/Mb
func BenchmarkRcxQuick(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		rcx.EncryptInplaceRcx(key, d, 32)
	}
}

// 0.5 sec/Mb
func BenchmarkRcxWithoutKeySchedule(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	var x rcx.RCX
	x.InitKey(key)
	for i := 0; i < b.N; i++ {
		x.EncryptCascade(d, 512)
	}
}

// 0.03 sec/Mb
func BenchmarkRcxQuickWithoutKeySchedule(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	var x rcx.RCX
	x.InitKey(key)
	for i := 0; i < b.N; i++ {
		x.EncryptCascade(d, 32)
	}
}

// 0.005 sec/Mb
func BenchmarkRcxQuickestWithoutKeySchedule(b *testing.B) {
	key := []byte("7eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304")
	d := make([]byte, 1000000)
	var x rcx.RCX
	x.InitKey(key)
	for i := 0; i < b.N; i++ {
		x.EncryptCascade(d, 4)
	}
}

// 0.2 sec
func BenchmarkSmallSize(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 128000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 0.5 sec
func BenchmarkL1(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 2 sec
func BenchmarkL5(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 5000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 4 sec
func BenchmarkL15(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 15000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 7 sec
func BenchmarkL20(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 20000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 7 sec
func BenchmarkL32(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 32000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 15 sec
func BenchmarkL40(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 40000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 16 sec
func BenchmarkL50(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 50000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 16 sec
func BenchmarkL64(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 64000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 32 sec
func BenchmarkL90(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 90000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// 34 sec
func BenchmarkL128(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 128000000)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(key, data)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
}

// func BenchmarkL256(b *testing.B) {
// 	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
// 	data := make([]byte, 256000000)
// 	for i := 0; i < b.N; i++ {
// 		_, err := Encrypt(key, data)
// 		if err != nil {
// 			b.Fatalf(err.Error())
// 		}
// 	}
// }

// func BenchmarkL512(b *testing.B) {
// 	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
// 	data := make([]byte, 512000000)
// 	for i := 0; i < b.N; i++ {
// 		_, err := Encrypt(key, data)
// 		if err != nil {
// 			b.Fatalf(err.Error())
// 		}
// 	}
// }

// 0.5 sec
func BenchmarkSteg(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 1000000)
	steg := make([]byte, len(data))
	for i := 0; i < b.N; i++ {
		_, err := EncryptSteg(key, data, steg)
		if err != nil {
			b.Fatalf("EncryptSteg error: %s", err.Error())
		}
	}
}

// 4 sec
func BenchmarkStegL10(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 10000000)
	steg := make([]byte, len(data))
	for i := 0; i < b.N; i++ {
		_, err := EncryptSteg(key, data, steg)
		if err != nil {
			b.Fatalf("EncryptSteg error: %s", err.Error())
		}
	}
}

// 32 sec
func BenchmarkStegL100(b *testing.B) {
	key := []byte("c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
	data := make([]byte, 100000000)
	steg := make([]byte, len(data))
	for i := 0; i < b.N; i++ {
		_, err := EncryptSteg(key, data, steg)
		if err != nil {
			b.Fatalf("EncryptSteg error: %s", err.Error())
		}
	}
}
