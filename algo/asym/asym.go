package asym

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/gluk256/crypto/algo/keccak"
)

// I am unable to implement elliptic curve cryptography, and therefore must rely on external libraries.
// These functions are imported from ethereum project, which is one of the most audited open source projects.

func Key(raw []byte) (key *ecdsa.PrivateKey, err error) {
	return crypto.ToECDSA(raw)
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func Sign(key *ecdsa.PrivateKey, data []byte) (signature []byte, err error) {
	hash := keccak.Digest(data, 32)
	return crypto.Sign(hash, key)
}

func Encrypt(key *ecdsa.PublicKey, data []byte) (res []byte, err error) {
	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(key), data, nil, nil)
}

func Decrypt(key *ecdsa.PrivateKey, data []byte) (res []byte, err error) {
	return ecies.ImportECDSA(key).Decrypt(data, nil, nil)
}

func SigToPub(data []byte, sig []byte) (pub *ecdsa.PublicKey, err error) {
	defer func() {
		pub = nil
		err = errors.New("invalid signature")
		recover()
	}()

	hash := keccak.Digest(data, 32)
	return crypto.SigToPub(hash, sig)
}
