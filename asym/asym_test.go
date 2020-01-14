package asym

import (
	"bytes"
	"crypto/ecdsa"
	"math/rand"
	"testing"
	"time"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
)

func TestGeneral(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("key generation failed: %s", err.Error())
	}

	if key.Params().BitSize != 256 {
		t.Fatalf("key size = %d", key.Params().BitSize)
	}

	singleKeyTest(t, key)

	data := generateRandomBytes(t)
	hash := keccak.Digest(data, 32)
	key, err = ImportPrivateKey(hash)
	if err != nil {
		t.Fatalf("key import failed: %s", err.Error())
	}

	singleKeyTest(t, key)

	k2, err := ImportPrivateKey(hash)
	if err != nil {
		t.Fatalf("key import failed: %s", err.Error())
	}

	p1, err := ExportPubKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("key export failed: %s", err.Error())
	}

	p2, err := ExportPubKey(&k2.PublicKey)
	if err != nil {
		t.Fatalf("key export failed: %s", err.Error())
	}

	if !bytes.Equal(p1, p2) {
		t.Fatal("consistency check failed")
	}

	if len(p1) != PublicKeySize {
		t.Fatalf("key export failed: wrong size [%d vs. %d]", len(p1), PublicKeySize)
	}
}

func singleKeyTest(t *testing.T, key *ecdsa.PrivateKey) {
	raw, err := ExportPubKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("key export failed: %s", err.Error())
	}

	pub, err := ImportPubKey(raw)
	if err != nil {
		t.Fatalf("re-import failed: %s", err.Error())
	}

	raw2, err := ExportPubKey(pub)
	if err != nil {
		t.Fatalf("re-export failed: %s", err.Error())
	}

	if !bytes.Equal(raw, raw2) {
		t.Fatal("re-export produced wrong key")
	}

	var data, sig []byte
	for i := 0; i < 8; i++ {
		data = generateRandomBytes(t)
		sig, err = Sign(key, data)
		if err != nil {
			t.Fatalf("sign failed: %s", err.Error())
		}

		if len(sig) != SignatureSize {
			t.Fatalf("wrong signature size: %d", len(sig))
		}

		recovered, err := SigToPub(data, sig)
		if err != nil {
			t.Fatalf("signature recovery failed: %s", err.Error())
		}

		if !bytes.Equal(raw, recovered) {
			t.Fatalf("signature recovery error\n%x vs. %x", raw, recovered)
		}

		j := rand.Int() % len(sig)
		sig[j]++
		r, err := SigToPub(data, sig)
		if err == nil {
			if bytes.Equal(r, raw) {
				t.Fatal("re-export false positive")
			}
		}
	}

	raw2[0]++
	pub, err = ImportPubKey(raw2)
	if err == nil {
		raw2, err = ExportPubKey(pub)
		if err != nil {
			t.Fatalf("second re-export failed: %s", err.Error())
		}

		if bytes.Equal(raw, raw2) {
			t.Fatal("re-export false positive")
		}
	}
}

func TestEncryption(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)

	for i := 0; i < 8; i++ {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("key generation failed: %s", err.Error())
		}

		orig := generateRandomBytes(t)
		x := make([]byte, len(orig))
		copy(x, orig)

		encrypted, err := Encrypt(&key.PublicKey, orig)
		if err != nil {
			t.Fatalf("encryption failed: %s", err.Error())
		}

		if !bytes.Equal(x, orig) {
			t.Fatal("orig destroyed")
		}

		ok := primitives.IsDeepNotEqual(orig, encrypted, len(orig))
		if !ok {
			t.Fatalf("failed encrypt deep check, round %d with seed %d", i, seed)
		}

		diff := len(encrypted) - len(orig)
		if diff != EncryptedSizeDiff {
			t.Fatalf("wrong encrypted size diff [%d vs. %d]", diff, EncryptedSizeDiff)
		}

		y := make([]byte, len(encrypted))
		copy(y, encrypted)

		decrypted, err := Decrypt(key, encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %s", err.Error())
		}

		if !bytes.Equal(decrypted, orig) {
			t.Fatalf("decryption bug, round %d with seed %d", i, seed)
		}

		if !bytes.Equal(y, encrypted) {
			t.Fatal("src destroyed")
		}

		j := rand.Int() % len(encrypted)
		encrypted[j]++
		decrypted, err = Decrypt(key, encrypted)
		if err == nil {
			t.Fatalf("decryption false positive: %s", err.Error())
		}
	}
}

func generateRandomBytes(t *testing.T) []byte {
	sz := rand.Intn(256) + 256
	b := make([]byte, sz)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatal("failed to generate random bytes")
	}
	return b
}

func BenchmarkDecryptShort(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatalf("key generation failed: %s", err.Error())
	}

	data := make([]byte, 1024)
	encrypted, err := Encrypt(&key.PublicKey, data)
	if err != nil {
		b.Fatalf("encryption failed: %s", err.Error())
	}

	for i := 0; i < b.N; i++ {
		_, err := Decrypt(key, encrypted)
		if err != nil {
			b.Fatalf("decryption failed: %s", err.Error())
		}
	}
}

func BenchmarkHash(b *testing.B) {
	data := make([]byte, 1024)

	for i := 0; i < b.N; i++ {
		keccak.Digest(data, 8)
	}
}
