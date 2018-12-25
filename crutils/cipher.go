package crutils

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/algo/rcx"
)

func EncryptKeccakInplace(key []byte, data []byte) {
	var d keccak.Keccak512
	d.Write(key)
	d.ReadXor(data)

	// cleanup internal state
	const sz = keccak.Rate * 4
	b := make([]byte, sz)
	d.ReadXor(b)
	primitives.ReverseByte(b[sz/2:])
	witness.Write(b)
}

func DecryptKeccakInplace(key []byte, data []byte) {
	EncryptKeccakInplace(key, data)
}

// don't forget to clear the data
func EncryptAES(key []byte, salt []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aesgcm.Seal(nil, salt, data, nil)
	return encrypted, err
}

// don't forget to clear the data
func DecryptAES(key []byte, salt []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	decrypted, err := aesgcm.Open(nil, salt, data, nil)
	return decrypted, err
}

// encryption level 0, rc4 + keccak, no salt, no padding, decryption == encryption
func EncryptInplaceLevelZero(key []byte, data []byte) {
	dummy := make([]byte, 1024*216)
	var rc4 rcx.RC4
	rc4.InitKey(key)
	rc4.XorInplace(dummy) // roll rc4 forward
	rc4.XorInplace(data)

	EncryptKeccakInplace(key, data)
}

// encryption level 1, rcx + keccak, no salt, no padding
func EncryptInplaceLevelOne(key []byte, data []byte, encrypt bool) {
	const iterations = 1025
	if encrypt {
		rcx.EncryptInplace(key, data, iterations)
		EncryptKeccakInplace(key, data)
	} else {
		DecryptKeccakInplace(key, data)
		rcx.DecryptInplace(key, data, iterations)
	}
}
