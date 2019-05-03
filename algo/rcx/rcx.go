package rcx

// this package must not import any dependencies

// RCX is a block cipher with block_size = 2 * number_of_iterations
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
	x.rc4.InitKey(key)
	x.shuffle()
}

func (x *RCX) shuffle() {
	for i := 0; i < 256 * 256; i++ {
		x.f[i] = uint16(i)
	}

	var cnt uint16
	for i := 0; i < 1024 * 8; i++ {
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

// this func expects the number of iterations to be odd,
// len(data)%4 == 0, and len(data) > 4
func (x *RCX) EncryptCascade(d []byte, iterations int) {
	x.encryptSingleRun(d)
	for i := 0; i < iterations/2; i++ {
		x.encryptSingleRun(d[2:len(d)-2])
		x.encryptSingleRun(d)
	}
}

func EncryptInplaceRCX(key []byte, d []byte, iterations int) {
	var x RCX
	x.InitKey(key)
	x.rc4.XorInplace(d)
	sz := len(d)
	if sz > 4 && iterations > 0 {
		odd := sz % 4
		x.EncryptCascade(d[:sz-odd], iterations)
	}
}

func DecryptInplaceRCX(key []byte, d []byte, iterations int) {
	var x RCX
	x.InitKey(key)
	sz := len(d)
	if sz > 4 && iterations > 0 {
		odd := sz % 4
		x.EncryptCascade(d[:sz-odd], iterations)
	}
	x.rc4.XorInplace(d)
}
