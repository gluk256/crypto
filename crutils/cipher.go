package crutils

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
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
