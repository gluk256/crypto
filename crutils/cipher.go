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
	SaltSize = 32
	EncryptedSizeDiffSteg = AesEncryptedSizeDiff + SaltSize
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

const (
	RcxFlag     = byte(0x01)
	AesFlag     = byte(0x02)
	PaddingFlag = byte(0x04)
	SpacingFlag = byte(0x08)
	QuickFlag   = byte(0x10)
	DefaultFlag = AesFlag | RcxFlag | SpacingFlag | PaddingFlag
)

func isRcx(flags byte) bool {
	return (flags & RcxFlag) != 0
}

func isAes(flags byte) bool {
	return (flags & AesFlag) != 0
}

func isSpacing(flags byte) bool {
	return (flags & SpacingFlag) != 0
}

func isPadding(flags byte) bool {
	return (flags & PaddingFlag) != 0
}

func EncryptInplaceKeccak(key []byte, data []byte) {
	var d keccak.Keccak512
	d.Write(key)
	d.ReadXor(data)
	b := make([]byte, keccak.Rate * 4)
	d.ReadXor(b) // cleanup internal state
	AnnihilateData(b) // prevent compiler optimization
}

// don't forget to clear the data
// key is expected to be 32 bytes, salt 12 bytes
func EncryptAES(key []byte, salt []byte, data []byte) ([]byte, error) {
	if len(key) != AesKeySize {
		fmt.Errorf("wrong key size %d", len(key))
	}
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
	if len(key) != AesKeySize {
		fmt.Errorf("wrong key size %d", len(key))
	}
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

func Encrypt(key []byte, data []byte, flags byte) ([]byte, error) {
	if isPadding(flags) {
		data, _ = addPadding(data, 0, true)
	}
	if isSpacing(flags) {
		data = addSpacing(data)
	}
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	keyholder := generateKeys(key, salt)
	defer AnnihilateData(keyholder)

	EncryptInplaceKeccak(keyholder[begK1:endK1], data)
	if isRcx(flags) {
		rcx.EncryptInplaceRCX(keyholder[begRcxKey:endRcxKey], data, (flags & QuickFlag) != 0)
	} else {
		rcx.EncryptInplaceRC4(keyholder[begRcxKey:endRcxKey], data)
	}
	if isAes(flags) {
		data, err = EncryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
		if err != nil {
			return nil, err
		}
		EncryptInplaceKeccak(keyholder[begK2:endK2], data)
	}
	salt[SaltSize-1] = flags
	data = append(data, salt...)
	return data, nil
}

func Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("no data")
	} else {
		return decryptWithFlags(key, data, data[len(data)-1])
	}
}

func decryptWithFlags(key []byte, data []byte, flags byte) (res []byte, err error) {
	if len(data) <= SaltSize {
		return nil, errors.New("salt consumed the data")
	}
	res = data[:len(data)-SaltSize]
	salt := data[len(data)-SaltSize:]
	keyholder := generateKeys(key, salt)
	defer AnnihilateData(keyholder)

	if isAes(flags) {
		EncryptInplaceKeccak(keyholder[begK2:endK2], res)
		res, err = DecryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], res)
		if err != nil {
			return nil, err
		}
	}
	if isRcx(flags) {
		rcx.DecryptInplaceRCX(keyholder[begRcxKey:endRcxKey], res, (flags & QuickFlag) != 0)
	} else {
		rcx.EncryptInplaceRC4(keyholder[begRcxKey:endRcxKey], res)
	}
	EncryptInplaceKeccak(keyholder[begK1:endK1], res)

	if isSpacing(flags) {
		res, _ = splitSpacing(res)
	}
	if isPadding(flags) {
		res, err = removePadding(res)
	}
	return res, err
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	err := StochasticRand(salt)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Stochastic rand failed: %s", err.Error()))
	}
	return salt, err
}

func generateKeys(key []byte, salt []byte) []byte {
	fullkey := make([]byte, 0, len(key) + len(salt))
	fullkey = append(fullkey, key...)
	fullkey = append(fullkey, salt...)
	fullkey = fullkey[:len(fullkey)-1]
	keyholder := keccak.Digest(fullkey, keyHolderSize)
	AnnihilateData(fullkey)
	return keyholder
}

// returns maximum possible size of raw steganographic content (without salt)
func getMaxRawStegSize(total int) int {
	raw := primitives.FindNextPowerOfTwo(total - EncryptedSizeDiffSteg)
	for raw + EncryptedSizeDiffSteg > total {
		raw /= 2
	}
	return raw
}

// encrypt with steganographic content as spacing
func EncryptSteg(key []byte, data []byte, steg []byte, quick bool) ([]byte, error) {
	var err error
	data, _ = addPadding(data, 0, true)
	if len(data) < len(steg) + 4 { // four bytes for padding bytes
		return nil, errors.New(fmt.Sprintf("data size is less than necessary [%d vs. %d]", len(data), len(steg)+4))
	}
	Rand(steg[len(steg)-1:]) // destroy flags
	steg, err = addPadding(steg, len(data), false) // no mark: steg content must be indistinguishable from random gamma
	if err != nil {
		return nil, err
	}

	// create spacing from data and steg
	b := make([]byte, 0, len(data)*2)
	for i := 0; i < len(data); i++ {
		b = append(b, data[i])
		b = append(b, steg[i])
	}

	flags := AesFlag | RcxFlag
	if quick {
		flags |= QuickFlag
	}

	res, err := Encrypt(key, b, flags)
	AnnihilateData(data)
	AnnihilateData(steg)
	return res, err
}

// decrypt data and extract raw steganographic content
func DecryptSteg(key []byte, src []byte) ([]byte, []byte, error) {
	res, err := Decrypt(key, src)
	if err != nil {
		return nil, nil, err
	}
	data, steg := splitSpacing(res)
	data, err = removePadding(data)
	return data, steg, err
}

// steganographic content is obviously of unknown size.
// however, we know that the size of original unencrypted steg content was power_of_two;
// so, we try all possible sizes (31 iterations at most, but in reality much less).
func DecryptStegContentOfUnknownSize(key []byte, steg []byte) ([]byte, error) {
	for sz := getMaxRawStegSize(len(steg)); sz > 0; sz /= 2 {
		trySize := sz + EncryptedSizeDiffSteg
		content := make([]byte, trySize)
		copy(content, steg[:trySize])
		res, err := decryptWithFlags(key, content, DefaultFlag)
		if err == nil {
			return res, err
		}
	}
	return nil, errors.New("failed to decrypt steganographic content")
}
