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
	EncryptedSizeDiff = AesEncryptedSizeDiff + SaltSize
	RcxIterationsDefault = 511
	RcxIterationsQuick = 37
	DefaultRollover = 1024 * 256
)

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

// keccak + rc4, xor only, no salt, no spacing/padding
// len(encrypted) == len(plaintext)
func EncryptInplaceLevelZero(key []byte, data []byte) {
	rcx.EncryptInplaceRC4(key, data, DefaultRollover)
	EncryptInplaceKeccak(key, data)
}

// keccak + rcx, no salt, no spacing/padding.
// this is a block cipher with block size of RcxIterations * 2.
// keccak should be applied before rcx (in case of encryption),
// in which case it will contribute to the security of the block cipher.
// len(encrypted) == len(plaintext)
func EncryptInplaceLevelOne(key []byte, data []byte, encrypt bool, quick bool) {
	iterations := RcxIterationsDefault
	if quick {
		iterations = RcxIterationsQuick
	}

	if encrypt {
		EncryptInplaceKeccak(key, data)
		rcx.EncryptInplaceRCX(key, data, iterations, encrypt)
	} else {
		rcx.EncryptInplaceRCX(key, data, iterations, encrypt)
		DecryptInplaceKeccak(key, data)
	}
}

// keccak + rcx with randomized spacing, no salt.
// randomized spacing significantly enhances the underlying block cipher
func EncryptLevelTwo(key []byte, data []byte, encrypt bool, quick bool) []byte {
	if encrypt { // encryption
		data = addSpacing(data)
	}

	EncryptInplaceLevelOne(key, data, encrypt, quick)

	if !encrypt { // decryption
		data, _ = splitSpacing(data)
	}

	return data
}

// keccak + rc4 + aes + keccak, xor only, with salt, no spacing/padding, very quick
func EncryptInplaceLevelThree(key []byte, data []byte, encrypt bool) ([]byte, error) {
	var res, salt []byte
	var err error

	if encrypt {
		salt = make([]byte, SaltSize)
		err = StochasticRand(salt)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Stochastic rand failed: %s", err.Error()))
		}
	} else {
		salt = data[len(data)-SaltSize:]
	}

	fullkey := make([]byte, 0, SaltSize + len(key))
	fullkey = append(fullkey, salt...)
	fullkey = append(fullkey, key...)
	keyholder := keccak.Digest(fullkey, keyHolderSize)

	if encrypt {
		EncryptInplaceKeccak(keyholder[begK1:endK1], data)
		rcx.EncryptInplaceRC4(keyholder[begRcxKey:endRcxKey], data, DefaultRollover)
		res, err = EncryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err == nil {
			EncryptInplaceKeccak(keyholder[begK2:endK2], res)
			res = append(res, salt...)
		}
	} else {
		data = data[:len(data)-SaltSize]
		EncryptInplaceKeccak(keyholder[begK2:endK2], data)
		res, err = DecryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err == nil {
			rcx.EncryptInplaceRC4(keyholder[begRcxKey:endRcxKey], res, DefaultRollover)
			DecryptInplaceKeccak(keyholder[begK1:endK1], res)
		}
	}

	AnnihilateData(fullkey)
	AnnihilateData(keyholder)
	return res, err
}

// keccak + rcx + aes + keccak, with salt, no spacing, no padding
func EncryptLevelFour(key []byte, data []byte, encrypt bool, quick bool) ([]byte, error) {
	return EncryptWithSalt(key, data, encrypt, quick)
}

// keccak + rcx + aes + keccak, with salt and spacing, no padding.
// randomized spacing significantly enhances the underlying block cipher.
func EncryptLevelFive(key []byte, data []byte, encrypt bool, quick bool) ([]byte, error) {
	return EncryptWithSaltAndSpacing(key, data, encrypt, quick)
}

// keccak + rcx + aes + keccak, with salt, spacing and padding.
// padding allows to conceal the content size.
func EncryptLevelSix(key []byte, data []byte, encrypt bool, quick bool) ([]byte, error) {
	if encrypt {
		data, _ = addPadding(data, 0, true)
	}
	res, err := EncryptWithSaltAndSpacing(key, data, encrypt, quick)
	if !encrypt {
		res, err = removePadding(res)
	}
	return res, err
}

// keccak + rcx + aes + keccak, with salt, no spacing, no padding
func EncryptWithSalt(key []byte, data []byte, encrypt bool, quick bool) ([]byte, error) {
	var res, salt []byte
	var err error
	iterations := RcxIterationsDefault
	if quick {
		iterations = RcxIterationsQuick
	}

	if encrypt {
		salt = make([]byte, SaltSize)
		err = StochasticRand(salt)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Stochastic rand failed: %s", err.Error()))
		}
	} else {
		salt = data[len(data)-SaltSize:]
	}

	fullkey := make([]byte, 0, SaltSize + len(key))
	fullkey = append(fullkey, salt...)
	fullkey = append(fullkey, key...)
	keyholder := keccak.Digest(fullkey, keyHolderSize)

	if encrypt {
		EncryptInplaceKeccak(keyholder[begK1:endK1], data)
		rcx.EncryptInplaceRCX(keyholder[begRcxKey:endRcxKey], data, iterations, encrypt)
		res, err = EncryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err == nil {
			EncryptInplaceKeccak(keyholder[begK2:endK2], res)
			res = append(res, salt...)
		}
	} else {
		data = data[:len(data)-SaltSize]
		EncryptInplaceKeccak(keyholder[begK2:endK2], data)
		res, err = DecryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err == nil {
			rcx.EncryptInplaceRCX(keyholder[begRcxKey:endRcxKey], res, iterations, encrypt)
			DecryptInplaceKeccak(keyholder[begK1:endK1], res)
		}
	}

	AnnihilateData(fullkey)
	AnnihilateData(keyholder)
	return res, err
}

// randomized spacing significantly enhances the underlying block cipher
func EncryptWithSaltAndSpacing(key []byte, data []byte, encrypt bool, quick bool) ([]byte, error) {
	if encrypt { // encryption
		data = addSpacing(data)
	}

	res, err := EncryptWithSalt(key, data, encrypt, quick)

	if !encrypt && err == nil { // decryption
		res, _ = splitSpacing(res)
	}

	return res, err
}

// encrypt with steganographic content as spacing
func EncryptSteg(key []byte, data []byte, steg []byte, quick bool) ([]byte, error) {
	var err error
	data, _ = addPadding(data, 0, true)
	if len(data) < len(steg) + 4 {
		return nil, errors.New(fmt.Sprintf("data size is less than necessary [%d vs. %d]", len(data), len(steg) + 4))
	}
	steg, err = addPadding(steg, len(data), false) // no mark - steg content should be indistinguishable from random
	if err != nil {
		return nil, err
	}

	// create spacing from data and steg
	b := make([]byte, 0, len(data)*2)
	for i := 0; i < len(data); i++ {
		b = append(b, data[i])
		b = append(b, steg[i])
	}

	res, err := EncryptWithSalt(key, b, true, quick)
	AnnihilateData(data)
	AnnihilateData(steg)
	return res, err
}

// decrypt data and extract raw steganographic content
func DecryptSteg(key []byte, src []byte, quick bool) ([]byte, []byte, error) {
	res, err := EncryptWithSalt(key, src, false, quick)
	if err != nil {
		return nil, nil, err
	}
	data, steg := splitSpacing(res)
	data, err = removePadding(data)
	return data, steg, err
}

// steganographic content is obviously of unknown size.
// however, we know that the size of original unencrypted steg content was power_of_two;
// so, we try all possible sizes (31 at most, but in reality much less).
func DecryptStegContentOfUnknownSize(key []byte, steg []byte, quick bool) ([]byte, error) {
	for sz := getMaxRawStegSize(len(steg)); sz > 0; sz /= 2 {
		trySize := sz + EncryptedSizeDiff
		content := make([]byte, trySize)
		copy(content, steg[:trySize])
		res, err := EncryptWithSaltAndSpacing(key, content, false, quick)
		if err == nil {
			res, err = removePadding(res)
			if err != nil {
				err = errors.New("xxx " + err.Error())
			}
			return res, err
		}
	}
	return nil, errors.New("failed to decrypt steganographic content")
}

// returns maximum possible size of raw steganographic content (without salt)
func getMaxRawStegSize(total int) int {
	raw := primitives.FindNextPowerOfTwo(total - EncryptedSizeDiff)
	for raw + EncryptedSizeDiff > total {
		raw /= 2
	}
	return raw
}
