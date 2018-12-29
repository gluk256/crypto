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
	AesEncryptedSizeDiff = 16
	SaltSize = 16
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
	primitives.ReverseBytes(b[sz/2:])
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

// keccak + rcx, no salt, no padding.
// rcx is a block cipher with block size of RcxIterations * 2.
// in case of encryption, keccak should be applied before rcx,
// in which case it will contribute to the security of the block cipher.
func EncryptInplaceLevelOne(key []byte, data []byte, encrypt bool) {
	if encrypt {
		EncryptInplaceKeccak(key, data)
		rcx.EncryptInplace(key, data, RcxIterations, encrypt)
	} else {
		rcx.EncryptInplace(key, data, RcxIterations, encrypt)
		DecryptInplaceKeccak(key, data)
	}
}

func EncryptLevelTwo(key []byte, data []byte, encrypt bool) ([]byte, error) {
	return EncryptWithSalt(key, data, encrypt, SaltSize)
}

func EncryptLevelFour(key []byte, data []byte, encrypt bool) ([]byte, error) {
	return EncryptWithSaltAndSpacing(key, data, encrypt)
}

func EncryptLevelFive(key []byte, data []byte, encrypt bool) ([]byte, error) {
	if encrypt {
		data = addPadding(data, true)
	}
	res, err := EncryptWithSaltAndSpacing(key, data, encrypt)
	if !encrypt {
		res, err = removePadding(res)
	}
	return res, err
}

// keccak + rxc + aes + keccak, with salt, no spacing, no padding
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

	if encrypt {
		EncryptInplaceKeccak(keyholder[begK1:endK1], data)
		rcx.EncryptInplace(keyholder[begRcxKey:endRcxKey], data, RcxIterations, encrypt)
		res, err = EncryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err == nil {
			EncryptInplaceKeccak(keyholder[begK2:endK2], res)
			res = append(res, salt...)
		}
	} else {
		data = data[:len(data)-saltsize]
		EncryptInplaceKeccak(keyholder[begK2:endK2], data)
		res, err = DecryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err == nil {
			rcx.EncryptInplace(keyholder[begRcxKey:endRcxKey], res, RcxIterations, encrypt)
			DecryptInplaceKeccak(keyholder[begK1:endK1], res)
		}
	}

	AnnihilateData(fullkey)
	AnnihilateData(keyholder)
	return res, err
}

// spacing is like a hidden salt, and hence more secure
func EncryptWithSaltAndSpacing(key []byte, data []byte, encrypt bool) ([]byte, error) {
	if encrypt { // encryption
		data = addSpacing(data, true)
	}

	res, err := EncryptWithSalt(key, data, encrypt, SaltSize)

	if !encrypt && err == nil { // decryption
		res, _ = splitSpacing(res, true)
	}

	return res, err
}

// with steganographic content
func EncryptSteg(key []byte, data []byte, steg []byte) ([]byte, error) {
	if len(data) != len(steg) {
		return nil, errors.New(fmt.Sprintf("data size is not equal steg size [%d vs. %d]", len(data), len(steg)))
	}
	b := make([]byte, 0, len(data)*2)
	for i := 0; i < len(data); i++ {
		b = append(b, data[i])
		b = append(b, steg[i])
	}
	res, err := EncryptWithSalt(key, b, true, SaltSize)
	return res, err
}

// with steganographic content
func DecryptSteg(key []byte, src []byte) ([]byte, []byte, error) {
	res, err := EncryptWithSalt(key, src, false, SaltSize)
	if err != nil {
		return nil, nil, err
	}
	data, steg := splitSpacing(res, true)
	return data, steg, err
}
