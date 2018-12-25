package crutils

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/algo/rcx"
)

func EncryptInplaceKeccak(key []byte, data []byte) {
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

func DecryptInplaceKeccak(key []byte, data []byte) {
	EncryptInplaceKeccak(key, data)
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

	EncryptInplaceKeccak(key, data)
}

// encryption level 1, rcx + keccak, no salt, no padding
func EncryptInplaceLevelOne(key []byte, data []byte, encrypt bool) {
	const iterations = 1025
	if encrypt {
		rcx.EncryptInplace(key, data, iterations)
		EncryptInplaceKeccak(key, data)
	} else {
		DecryptInplaceKeccak(key, data)
		rcx.DecryptInplace(key, data, iterations)
	}
}

// encryption level 2, keccak + rxc + aes + keccak, with salt, no padding
func EncryptLevelTwo(key []byte, data []byte, encrypt bool) ([]byte, error) {
	const (
		saltsize = 16
		b1 = 200
		e1 = b1 + 256
		bk = 600
		ek = bk + 256
		ba = 1000
		ea = ba + 32
		bs = 1200
		es = bs + 12
	)

	var res, salt []byte
	var err error
	if encrypt {
		salt = make([]byte, saltsize)
		err = StochasticRand(salt)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Stocastic rand failed: %s", err.Error()))
		}
	} else {
		salt = data[len(data)-saltsize:]
	}

	fullkey := make([]byte, saltsize + len(key))
	copy(fullkey, salt)
	copy(fullkey[:saltsize], key)
	keyholder := keccak.Digest(fullkey, es)
	defer AnnihilateData(fullkey)

	if encrypt {
		EncryptInplaceLevelOne(keyholder[b1:e1], data, true)
		res, err = EncryptAES(keyholder[ba:ea], keyholder[bs:es], data)
		if err != nil {
			return nil, err
		}
		EncryptInplaceKeccak(keyholder[bk:ek], res)
		res = append(res, salt...)
	} else {
		data = data[:len(data)-saltsize]
		EncryptInplaceKeccak(keyholder[bk:ek], data)
		res, err = DecryptAES(keyholder[ba:ea], keyholder[bs:es], data)
		if err != nil {
			return nil, err
		}
		EncryptInplaceLevelOne(keyholder[b1:e1], res, false)
	}
	return res, nil
}
