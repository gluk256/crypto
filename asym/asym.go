package asym

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/crutils"
)

// I am unable to implement elliptic curve cryptography, and have to rely on external libraries.
// These functions are imported from ethereum - one of the most audited open source projects.

const EncryptedSizeDiff = 113

func ImportPrivateKey(raw []byte) (key *ecdsa.PrivateKey, err error) {
	return crypto.ToECDSA(raw)
}

func GenerateKey() (key *ecdsa.PrivateKey, err error) {
	raw := make([]byte, 32)
	err = crutils.StochasticRand(raw)
	if err == nil {
		key, err = ImportPrivateKey(raw)
	}
	return key, err
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

func AnnihilateBigInt(i *big.Int) {
	arr := i.Bits()
	sz := len(arr)
	for i := sz - 1; i >= 0; i-- {
		u, _ := crutils.StochasticUint64() // ignore the errors, because the pseudorandom entropy is good enough
		arr[i] ^= big.Word(u)
	}
	for i := 0; i < sz; i++ {
		crutils.RecordDestruction(uint64(arr[i]))
	}
	for i := 0; i < sz; i++ {
		crutils.RecordDestruction(uint64(arr[i]))
	}
}

func AnnihilatePubKey(k *ecdsa.PublicKey) {
	if k != nil {
		AnnihilateBigInt(k.X)
		AnnihilateBigInt(k.Y)
	}
}

func AnnihilatePrivateKey(k *ecdsa.PrivateKey) {
	if k != nil {
		AnnihilateBigInt(k.D)
		AnnihilatePubKey(&k.PublicKey)
	}
}
