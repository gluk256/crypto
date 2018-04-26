package keccak

import (
	"unsafe"

	"github.com/gluk256/crypto/algo/primitives"
)

const Rate = 72

type Keccak512 struct {
	a [25]uint64
	storage [Rate]byte
	absorbing bool
	buf []byte // points into storage
}

func xorIn(d *Keccak512, in []byte) {
	const sz = Rate / 8
	b := (*[sz]uint64)(unsafe.Pointer(&in[0]))
	for j := 0; j < sz; j++ {
		d.a[j] ^= b[j]
	}
}

func copyOut(d *Keccak512, buf []byte) {
	ab := (*[Rate]uint8)(unsafe.Pointer(&d.a[0]))
	copy(buf, ab[:])
}

func (d *Keccak512) absorb() {
	xorIn(d, d.buf)
	d.buf = d.storage[:0]
	keccakF1600(&d.a)
}

func (d *Keccak512) squeeze() {
	keccakF1600(&d.a)
	d.buf = d.storage[:Rate]
	copyOut(d, d.buf)
}

// appends the domain separation bits in dsbyte,
// applies the padding rule, and permutes the state.
func (d *Keccak512) finalize() {
	if d.buf == nil {
		d.buf = d.storage[:0]
	}
	// Pad with this instance's domain-separator bits. We know that there's
	// at least one byte of space in d.buf because, if it were full,
	// permute would have been called to empty it. dsbyte also contains the
	// first one bit for the padding. See the comment in the state struct.
	const dsbyte = byte(0x01)
	d.buf = append(d.buf, dsbyte)
	zerosStart := len(d.buf)
	d.buf = d.storage[:Rate]
	for i := zerosStart; i < Rate; i++ {
		d.buf[i] = 0
	}
	d.buf[Rate-1] ^= 0x80
	d.absorb()
	d.buf = d.storage[:Rate]
	copyOut(d, d.buf)
	d.absorbing = false
}

func (d *Keccak512) read(out []byte, xor bool) {
	if d.absorbing {
		d.finalize()
	}

	for len(out) > 0 {
		var n int
		if xor {
			n = primitives.Min(len(out), len(d.buf))
			primitives.XorInplace(out, d.buf, n)
		} else {
			n = copy(out, d.buf)
		}

		d.buf = d.buf[n:]
		out = out[n:]

		// apply the permutation if the sponge was squeezed dry
		if len(d.buf) == 0 {
			d.squeeze()
		}
	}
}

func (d *Keccak512) Read(out []byte) {
	d.read(out, false)
}

func (d *Keccak512) ReadXor(out []byte) {
	d.read(out, true)
}

// Write absorbs more data into the hash's state. It produces an error
// if more data is written to the ShakeHash after writing
func (d *Keccak512) Write(p []byte) {
	d.absorbing = true
	if d.buf == nil {
		d.buf = d.storage[:0]
	}

	for len(p) > 0 {
		if len(d.buf) == 0 && len(p) >= Rate {
			// The fast path; absorb a full "rate" bytes of input and apply the permutation.
			xorIn(d, p[:Rate])
			p = p[Rate:]
			keccakF1600(&d.a)
		} else {
			// The slow path; buffer the input until we can fill the sponge, and then xor it in.
			todo := Rate - len(d.buf)
			if todo > len(p) {
				todo = len(p)
			}
			d.buf = append(d.buf, p[:todo]...)
			p = p[todo:]

			// If the sponge is full, apply the permutation.
			if len(d.buf) == Rate {
				d.absorb()
			}
		}
	}
}

func Digest(in []byte, sz int) []byte {
	var d Keccak512
	d.Write(in)
	out := make([]byte, sz)
	d.Read(out)
	return out
}
