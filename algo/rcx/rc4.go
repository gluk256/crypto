package rcx

// this package must not import any dependencies

type RC4 struct {
	s    [256]byte
	i, j byte
}

func (c *RC4) InitKey(key []byte) {
	for i := 0; i < 256; i++ {
		c.s[i] = byte(i)
	}
	for i := 0; i < 256; i++ {
		c.j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[c.j] = c.s[c.j], c.s[i]
	}
}

func (c *RC4) XorInplace(data []byte) {
	for n := 0; n < len(data); n++ {
		c.i++
		c.j += c.s[c.i]
		c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
		x := c.s[c.i] + c.s[c.j]
		data[n] ^= c.s[x]
	}
}

func EncryptInplaceRC4(key []byte, data []byte) {
	var x RC4
	x.InitKey(key)
	rollover := int(x.s[255]) + int(x.s[x.j])*256 + 256*256
	dummy := make([]byte, rollover)
	x.XorInplace(dummy) // roll forward
	x.XorInplace(data)
}
