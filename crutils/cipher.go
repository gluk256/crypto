package crutils

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"reflect"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/rcx"
)

const (
	Version              = 2
	AesKeySize           = 32
	AesSaltSize          = 12
	AesEncryptedSizeDiff = 16
	SaltSize             = 48
	MinDataSize          = 64
	EncryptedSizeDiff    = AesEncryptedSizeDiff + SaltSize
)

const (
	offset        = 256
	begK1         = offset
	endK1         = begK1 + offset
	begK2         = endK1 + offset
	endK2         = begK2 + offset
	begRcxKey     = endK2 + offset
	endRcxKey     = begRcxKey + offset
	begAesKey     = endRcxKey + offset
	endAesKey     = begAesKey + AesKeySize
	begAesSalt    = endAesKey + offset
	endAesSalt    = begAesSalt + AesSaltSize
	keyHolderSize = endAesSalt
)

func calculateRcxIterations(sz int) int {
	const Kb = 1024
	const Mb = Kb * 1024
	if sz < Kb*32 {
		return 4096
	} else if sz < Kb*128 {
		return 2048
	} else if sz < Kb*256 {
		return 1024
	} else if sz < Kb*512 {
		return 512
	} else if sz < Mb*1 {
		return 256
	} else if sz < Mb*2 {
		return 128
	} else if sz < Mb*4 {
		return 64
	} else if sz < Mb*8 {
		return 32
	} else if sz < Mb*16 {
		return 16
	} else if sz < Mb*25 {
		return 12
	} else if sz < Mb*32 {
		return 8
	} else {
		return 4
	}
}

func EncryptInplaceRCX(key []byte, data []byte) {
	cleanup := rcx.EncryptInplaceRcx(key, data, calculateRcxIterations(len(data)))
	AnnihilateData(cleanup)
}

func DecryptInplaceRCX(key []byte, data []byte) {
	cleanup := rcx.DecryptInplaceRcx(key, data, calculateRcxIterations(len(data)))
	AnnihilateData(cleanup)
}

func EncryptInplaceKeccak(key []byte, data []byte) {
	var d keccak.Keccak512
	d.Write(key)
	d.ReadXor(data)

	// cleanup
	b := make([]byte, keccak.Rate*4)
	d.ReadXor(b)
	AnnihilateData(b) // prevent compiler optimization
}

// key is expected to be 32 bytes, salt 12 bytes
func EncryptAES(key []byte, salt []byte, data []byte) ([]byte, error) {
	if len(key) != AesKeySize {
		return nil, fmt.Errorf("wrong key size %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aesgcm.Seal(data[:0], salt, data, nil)
	return encrypted, err
}

// key is expected to be 32 bytes, salt 12 bytes
func DecryptAES(key []byte, salt []byte, data []byte) ([]byte, error) {
	if len(key) != AesKeySize {
		return nil, fmt.Errorf("wrong key size %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	decrypted, err := aesgcm.Open(data[:0], salt, data, nil)
	return decrypted, err
}

// this is the main encryption function
func Encrypt(key []byte, data []byte) ([]byte, error) {
	data, _ = addPadding(data, 0, true)
	spacing := make([]byte, len(data))
	Randomize(spacing)
	return encryptWithSpacing(key, data, spacing)
}

// encrypt with steganographic content as spacing
func EncryptSteg(key []byte, data []byte, steg []byte) (res []byte, err error) {
	data, _ = addPadding(data, 0, true)
	if len(data) < len(steg)+4 { // four bytes for padding size
		return nil, fmt.Errorf("data size is less than necessary [%d vs. %d]", len(data), len(steg)+4)
	}
	steg, err = addPadding(steg, len(data), false) // mark = false: steg content must be indistinguishable from random gamma
	if err != nil {
		return nil, err
	}

	res, err = encryptWithSpacing(key, data, steg)
	return res, err
}

// data must be already padded.
// don't forget to annihilate the key!
func encryptWithSpacing(key []byte, data []byte, spacing []byte) ([]byte, error) {
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	data = addSpacing(data, spacing) // now data will have additional capacity (enough for the salt)
	keyholder := generateKeys(key, salt)
	defer AnnihilateData(keyholder)

	EncryptInplaceKeccak(keyholder[begK1:endK1], data)
	EncryptInplaceRCX(keyholder[begRcxKey:endRcxKey], data)
	tmp, err := EncryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], data)
	if err != nil {
		return nil, err
	}
	reallocated := reflect.ValueOf(tmp).Pointer() != reflect.ValueOf(data).Pointer()
	if reallocated {
		fmt.Println("WARNING: data reallocated during AES encryption and not annihilated!")
	}
	data = tmp
	EncryptInplaceKeccak(keyholder[begK2:endK2], data)
	res := append(data, salt...)
	reallocated = reflect.ValueOf(res).Pointer() != reflect.ValueOf(data).Pointer()
	if reallocated {
		fmt.Println("WARNING: data reallocated because of append, and not annihilated!")
	}
	return res, nil
}

// don't forget to annihilate the key!
func Decrypt(key []byte, data []byte) (res []byte, spacing []byte, err error) {
	if len(data) <= SaltSize {
		return nil, nil, fmt.Errorf("data size %d, less than salt size %d", len(data), SaltSize)
	}
	res = data[:len(data)-SaltSize]
	salt := data[len(data)-SaltSize:]
	keyholder := generateKeys(key, salt)
	defer AnnihilateData(keyholder)

	EncryptInplaceKeccak(keyholder[begK2:endK2], res)
	res, err = DecryptAES(keyholder[begAesKey:endAesKey], keyholder[begAesSalt:endAesSalt], res)
	if err != nil {
		return nil, nil, err
	}
	DecryptInplaceRCX(keyholder[begRcxKey:endRcxKey], res)
	EncryptInplaceKeccak(keyholder[begK1:endK1], res)

	res, spacing = splitSpacing(res)
	res, err = removePadding(res)
	return res, spacing, err
}

// steganographic content is obviously of unknown size.
// however, we assume that original unencrypted steg content was padded (size=power_of_two);
// so, we try all possible sizes (25 iterations at most, but in reality much less).
func DecryptStegContentOfUnknownSize(key []byte, steg []byte) ([]byte, []byte, error) {
	for sz := len(steg) / 2; sz >= MinDataSize; sz /= 2 {
		trySize := sz + EncryptedSizeDiff
		content := make([]byte, trySize)
		copy(content, steg[:trySize])
		res, steg, err := Decrypt(key, content)
		if err == nil {
			return res, steg, err
		}
	}
	return nil, nil, errors.New("failed to decrypt steganographic content")
}
