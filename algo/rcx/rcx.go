package rcx

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

	var arr [512]byte
	var cnt uint16
	for i := 0; i < 256 * 4; i++ {
		x.r.XorInplace(arr[:])
		for j := 0; j < 512; j += 2 {
			v := Bytes2uint(arr[j], arr[j+1])
			x.f[cnt], x.f[v] = x.f[v], x.f[cnt]
			cnt++
		}
	}
}

// this func expects len(data)%4 == 0
func (x *RCX) encryptSingleIteration(d []byte) {
	for i := 0; i < len(d); i += 4 {
		a := Bytes2uint(d[i], d[i+1])
		b := Bytes2uint(d[i+2], d[i+3])
		y := x.f[a] ^ b
		z := x.f[y] ^ a
		d[i], d[i+1] = Uint2bytes(y)
		d[i+2], d[i+3] = Uint2bytes(z)
	}
}

// this func expects len(data)%4 == 0
func (x *RCX) decryptSingleIteration(d []byte) {
	for i := 0; i < len(d); i += 4 {
		y := Bytes2uint(d[i], d[i+1])
		z := Bytes2uint(d[i+2], d[i+3])
		a := x.f[y] ^ z
		b := x.f[a] ^ y
		d[i], d[i+1] = Uint2bytes(a)
		d[i+2], d[i+3] = Uint2bytes(b)
	}
}

// this func expects the number of iterations to be odd,
// len(data)%4 == 0, and len(data) > 4
func (x *RCX) encryptCascade(d []byte, iterations int) {
	x.encryptSingleIteration(d)
	for i := 0; i < iterations/2; i++ {
		x.encryptSingleIteration(d[2:len(d)-2])
		x.encryptSingleIteration(d)
	}
}

// this func expects the number of iterations to be odd,
// len(data)%4 == 0 and len(data) > 4
func (x *RCX) decryptCascade(d []byte, iterations int) {
	x.decryptSingleIteration(d)
	for i := 0; i < iterations/2; i++ {
		x.decryptSingleIteration(d[2:len(d)-2])
		x.decryptSingleIteration(d)
	}
}

// this func expects the number of iterations to be odd,
// len(data)%4 == 0, and len(data) > 4
func EncryptInplace(key []byte, d []byte, iterations int) {
	var x RCX
	x.InitKey(key)
	x.r.XorInplace(d)
	if iterations > 0 {
		x.encryptCascade(d, iterations)
	}
}

// this func expects the number of iterations to be odd,
// len(data)%4 == 0 and len(data) > 4
func DecryptInplace(key []byte, d []byte, iterations int) {
	var x RCX
	x.InitKey(key)
	if iterations > 0 {
		x.decryptCascade(d, iterations)
	}
	x.r.XorInplace(d)
}