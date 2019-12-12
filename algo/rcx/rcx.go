package rcx

// this package must not import any dependencies

// RCX is a block cipher with block_size = number_of_iterations + 4
// this cipher is very simple, optimized for readability

type RCX struct {
	rc4 RC4
	f   [256 * 256]uint16
}

func Bytes2uint(a, b byte) uint16 {
	ub := uint16(b) << 8
	ua := uint16(a)
	return ua + ub
}

func Uint2bytes(i uint16) (byte, byte) {
	a := byte(i)
	b := byte(i >> 8)
	return a, b
}

func (x *RCX) InitKey(key []byte) {
	for i := 0; i < 256*256; i++ {
		x.f[i] = uint16(i)
	}

	x.rc4.InitKey(key)
	x.shuffle(4096)
}

func (x *RCX) shuffle(rounds int) {
	var cnt uint16
	for r := 0; r < rounds; r++ {
		a1 := make([]byte, 256)
		a2 := make([]byte, 256)
		x.rc4.XorInplace(a1[:])
		x.rc4.XorInplace(a2[:])
		for j := 0; j < 256; j++ {
			z := Bytes2uint(a1[j], a2[j])
			x.f[cnt], x.f[z] = x.f[z], x.f[cnt]
			cnt++
		}
	}
}

func (x *RCX) cleanup() []byte {
	const c = 256 * 3
	x.shuffle(c)
	x.EncryptCascade(x.rc4.s[:], c)
	return x.rc4.s[:]
}

// this func expects len(data)%4 == 0
func (x *RCX) encryptSingleRun(d []byte) {
	for i := 0; i < len(d); i += 4 {
		a := Bytes2uint(d[i], d[i+1])
		b := Bytes2uint(d[i+2], d[i+3])
		y := x.f[a] ^ b
		z := x.f[y] ^ a
		d[i], d[i+1] = Uint2bytes(y)
		d[i+2], d[i+3] = Uint2bytes(z)
	}
}

// this func expects the number of iterations to be divisible by 4, len(data)%4 == 0, and len(data) > 4
func (x *RCX) EncryptCascade(d []byte, iterations int) {
	for i := 0; i < iterations/4; i++ {
		x.encryptSingleRun(d)
		x.encryptSingleRun(d[1 : len(d)-3])
		x.encryptSingleRun(d[2 : len(d)-2])
		x.encryptSingleRun(d[3 : len(d)-1])
	}

	x.encryptSingleRun(d)
}

// this func expects the number of iterations to be divisible by 4, len(data)%4 == 0, and len(data) > 4
func (x *RCX) DecryptCascade(d []byte, iterations int) {
	x.encryptSingleRun(d)

	for i := 0; i < iterations/4; i++ {
		x.encryptSingleRun(d[3 : len(d)-1])
		x.encryptSingleRun(d[2 : len(d)-2])
		x.encryptSingleRun(d[1 : len(d)-3])
		x.encryptSingleRun(d)
	}
}

func EncryptInplaceRcx(key []byte, d []byte, iterations int) []byte {
	var x RCX
	x.InitKey(key)
	x.rc4.XorInplace(d)
	sz := len(d)
	if sz > 4 && iterations > 0 {
		odd := sz % 4
		x.EncryptCascade(d[:sz-odd], iterations)
	}

	return x.cleanup()
}

func DecryptInplaceRcx(key []byte, d []byte, iterations int) []byte {
	var x RCX
	x.InitKey(key)
	sz := len(d)
	if sz > 4 && iterations > 0 {
		odd := sz % 4
		x.DecryptCascade(d[:sz-odd], iterations)
	}
	x.rc4.XorInplace(d)

	return x.cleanup()
}
