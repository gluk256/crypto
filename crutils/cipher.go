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

const (
	AesKeySize = 32
	AesSaltSize = 12
	RcxIterations = 1025
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
// key is expected to be 32 bytes, salt 12 bytes
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

// rc4 + keccak, no salt, no padding, xor only, decryption == encryption
func EncryptInplaceLevelZero(key []byte, data []byte) {
	dummy := make([]byte, 1024*216)
	var rc4 rcx.RC4
	rc4.InitKey(key)
	rc4.XorInplace(dummy) // roll rc4 forward
	rc4.XorInplace(data)

	EncryptInplaceKeccak(key, data)
}

// keccak + rcx, no salt, no padding
// for encryption keccak should be applied before rcx
func EncryptInplaceLevelOne(key []byte, data []byte, encrypt bool) {
	if encrypt {
		EncryptInplaceKeccak(key, data)
		rcx.EncryptInplace(key, data, RcxIterations, encrypt)
	} else {
		rcx.EncryptInplace(key, data, RcxIterations, encrypt)
		DecryptInplaceKeccak(key, data)
	}
}

// keccak + rxc + aes + keccak, with salt, no padding
func EncryptWithSalt(key []byte, data []byte, encrypt bool, saltsize int) ([]byte, error) {
	const (
		offset = 256
		begK1 = offset
		endK1 = begK1 + offset
		begK2 = endK1 + offset
		endK2 = begK2 + offset
		begRcxKey = endK2 + offset
		endRcxKey = begRcxKey + offset
		begAesKey = endRcxKey + offset
		endAesKey = begAesKey + AesKeySize
		begAesSalt = endAesKey + offset
		endAesSalt = begAesSalt + AesSaltSize
		keyHolderSize = endAesSalt
	)

	var res, salt []byte
	var err error
	if encrypt {
		salt = make([]byte, saltsize)
		err = StochasticRand(salt)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Stochastic rand failed: %s", err.Error()))
		}
	} else {
		salt = data[len(data)-saltsize:]
	}

	fullkey := make([]byte, 0, saltsize + len(key))
	fullkey = append(fullkey, salt...)
	fullkey = append(fullkey, key...)
	keyholder := keccak.Digest(fullkey, keyHolderSize)
	defer AnnihilateData(fullkey)

	if encrypt {
		EncryptInplaceKeccak(keyholder[begK1:endK1], data)
		rcx.EncryptInplace(keyholder[begRcxKey:endRcxKey], data, RcxIterations, encrypt)
		res, err = EncryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err != nil {
			return nil, err
		}
		EncryptInplaceKeccak(keyholder[begK2:endK2], res)
		res = append(res, salt...)
	} else {
		data = data[:len(data)-saltsize]
		EncryptInplaceKeccak(keyholder[begK2:endK2], data)
		res, err = DecryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err != nil {
			return nil, err
		}
		rcx.EncryptInplace(keyholder[begRcxKey:endRcxKey], res, RcxIterations, encrypt)
		DecryptInplaceKeccak(keyholder[begK1:endK1], res)
	}

	return res, nil
}

func EncryptLevelTwo(key []byte, data []byte, encrypt bool) ([]byte, error) {
	return EncryptWithSalt(key, data, encrypt, 16)
}

func EncryptLevelThree(key []byte, data []byte, encrypt bool) ([]byte, error) {
	return EncryptWithSalt(key, data, encrypt, 64)
}

func EncryptLevelFour(key []byte, data []byte, encrypt bool) ([]byte, error) {
	return EncryptWithSaltAndSpacing(key, data, encrypt)
}

// with pseudorandom spacing
func EncryptWithSaltAndSpacing(key []byte, data []byte, encrypt bool) ([]byte, error) {
	var b []byte
	defer AnnihilateData(b)

	if encrypt {
		b = make([]byte, 0, len(data)*2)
		rnd := make([]byte, len(data))
		Rand(rnd)
		for i := 0; i < len(data); i++ {
			b = append(b, data[i])
			b = append(b, rnd[i])
		}
		b, data = data, b
	}

	res, err := EncryptWithSalt(key, data, encrypt, 64)

	if !encrypt && err == nil {
		b = make([]byte, 0, len(res)/2)
		for i := 0; i < len(res); i += 2 {
			b = append(b, res[i])
		}
		b, res = res, b
	}

	return res, err
}
