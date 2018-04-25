package crutils

import (
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
