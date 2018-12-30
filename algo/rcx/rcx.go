package rcx

// RCX is a block cipher with block_size = 2 * number_of_iterations
// this cipher is very simple, optimized for readability

type RCX struct {
	r RC4
	f [256 * 256]uint16
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
	x.r.InitKey(key)
	x.shuffle()
}

func (x *RCX) shuffle() {
	for i := 0; i < 256 * 256; i++ {
		x.f[i] = uint16(i)
	}

	var cnt uint16
	for i := 0; i < 1024 * 8; i++ {
		arr := make([]byte, 512)
		x.r.XorInplace(arr[:])
		for j := 0; j < 512; j += 2 {
			v := Bytes2uint(arr[j], arr[j+1])
			x.f[cnt], x.f[v] = x.f[v], x.f[cnt]
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
func (x *RCX) encryptCascade(d []byte, iterations int) {
	x.encryptSingleRun(d)
	for i := 0; i < iterations/2; i++ {
		x.encryptSingleRun(d[2:len(d)-2])
		x.encryptSingleRun(d)
	}
}

// this func expects the number of iterations to be odd, decryption == encryption
func EncryptInplace(key []byte, d []byte, iterations int, encrypt bool) {
	var x RCX
	x.InitKey(key)

	if encrypt { // in case of encryption
		x.r.XorInplace(d)
	}

	sz := len(d)
	if iterations > 0 && sz > 4 {
		odd := sz % 4
		x.encryptCascade(d[:sz-odd], iterations)
	}

	if !encrypt { // in case of decryption
		x.r.XorInplace(d)
	}
}
