package keccak

import (
	"unsafe"

	"github.com/gluk256/crypto/algo/primitives"
)

const Rate = 72

type Keccak512 struct {
	absorbing bool
	a         [25]uint64
	storage   [Rate]byte
	buf       []byte // points into storage
}

// copy [Rate] bytes of src into the state
// we assume that at this point len(src) == Rate
func (k *Keccak512) absorb(src []byte) {
	const sz = Rate / 8
	s := (*[sz]uint64)(unsafe.Pointer(&src[0]))
	for j := 0; j < sz; j++ {
		k.a[j] ^= s[j]
	}
}

// copy [Rate] bytes of state into the storage
func (k *Keccak512) squeeze() {
	k.buf = k.storage[:Rate]
	src := (*[Rate]uint8)(unsafe.Pointer(&k.a[0]))
	copy(k.buf, src[:])
}

// appends the domain separation bits in dsbyte, applies the padding rule, and permutes the state
func (k *Keccak512) finalize() {
	if k.buf == nil {
		k.buf = k.storage[:0]
	}
	// Pad with this instance's domain-separator bits.
	// We know that there's at least one byte of space in d.buf,
	// because if it were full, permute would have been called to empty it.
	// DS-byte also contains the first one bit for the padding.
	const dsbyte = byte(0x01)
	k.buf = append(k.buf, dsbyte)

	// fill unused bytes of storage with zeros
	zerosStart := len(k.buf)
	k.buf = k.storage[:Rate]
	for i := zerosStart; i < Rate; i++ {
		k.buf[i] = 0
	}

	k.buf[Rate-1] ^= 0x80
	k.absorb(k.buf)
	permute(&k.a)
	k.squeeze()
	k.absorbing = false
}

func (k *Keccak512) read(dst []byte, xor bool) {
	if k.absorbing {
		k.finalize()
	}

	for len(dst) > 0 {
		n := primitives.Min(len(dst), len(k.buf))
		if xor {
			primitives.XorInplace(dst, k.buf, n)
		} else {
			n = copy(dst, k.buf)
		}

		k.buf = k.buf[n:]
		dst = dst[n:]

		// apply the permutation if the sponge is empty
		if len(k.buf) == 0 {
			permute(&k.a)
			k.squeeze()
		}
	}
}

func (k *Keccak512) Read(dst []byte) {
	k.read(dst, false)
}

func (k *Keccak512) ReadXor(dst []byte) {
	k.read(dst, true)
}

func (k *Keccak512) Write(src []byte) {
	if !k.absorbing || k.buf == nil {
		k.buf = k.storage[:0]
	}
	k.absorbing = true

	for len(src) > 0 {
		if len(k.buf) == 0 && len(src) >= Rate {
			// fast path: absorb a full [len==Rate] of input bytes and apply the permutation
			k.absorb(src[:Rate])
			src = src[Rate:]
			permute(&k.a)
		} else {
			// slow path: buffer the input until we can fill the sponge, and then xor it in
			leftover := Rate - len(k.buf)
			if leftover > len(src) {
				leftover = len(src)
			}
			k.buf = append(k.buf, src[:leftover]...)
			src = src[leftover:]

			// if the sponge is full, apply the permutation
			if len(k.buf) == Rate {
				k.absorb(k.buf)
				k.buf = k.storage[:0]
				permute(&k.a)
			}
		}
	}
}

func Digest(src []byte, sz int) []byte {
	res := make([]byte, sz)
	var k Keccak512
	k.Write(src)
	k.Read(res)
	return res
}

// working with wntropy ////////////////////////////////////////////

func (k *Keccak512) AddEntropy(e uint64) {
	j := (k.a[0] + e) % 25
	k.a[j] ^= e
	permute(&k.a)
}

func (k *Keccak512) RandUint64() uint64 {
	permute(&k.a)
	j := k.a[0] % 25
	res := k.a[j]
	defer permute(&k.a)
	return res
}
