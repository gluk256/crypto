package asym

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/gluk256/crypto/algo/keccak"
)

// I am unable to implement elliptic curve cryptography, and have to rely on external libraries.
// These functions are imported from ethereum - one of the most audited open source projects.

const EncryptedSizeDiff = 113

func ImportPrivateKey(raw []byte) (key *ecdsa.PrivateKey, err error) {
	return crypto.ToECDSA(raw)
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func ExportPubKey(key *ecdsa.PublicKey) (res []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Warning: ExportPubKey failed: ", r)
			err = errors.New("ExportPubKey failed")
		}
	}()

	res = crypto.CompressPubkey(key)
	return res, err
}

func ImportPubKey(data []byte) (res *ecdsa.PublicKey, err error) {
	return crypto.DecompressPubkey(data)
}

func Sign(key *ecdsa.PrivateKey, data []byte) (signature []byte, err error) {
	hash := keccak.Digest(data, 32)
	return crypto.Sign(hash, key)
}

func SigToPub(data []byte, sig []byte) (res []byte, err error) {
	var pub *ecdsa.PublicKey
	hash := keccak.Digest(data, 32)
	pub, err = crypto.SigToPub(hash, sig)
	if err == nil {
		res, err = ExportPubKey(pub)
	}
	return res, err
}

func Encrypt(key *ecdsa.PublicKey, data []byte) (res []byte, err error) {
	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(key), data, nil, nil)
}

func Decrypt(key *ecdsa.PrivateKey, data []byte) (res []byte, err error) {
	return ecies.ImportECDSA(key).Decrypt(data, nil, nil)
}
