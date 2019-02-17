package rcx

// this package must not import any dependencies

type RC4 struct {
	s [256]byte
	i, j byte
}

func (c *RC4) Reset() {
	c.j = 0
}

func (c *RC4) InitKey(key []byte) {
	for i := 0; i < 256; i++ {
		c.s[i] = byte(i)
	}
	for i := 0; i < 256; i++ {
		c.j += c.s[i] + key[i % len(key)]
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
	var rc4 RC4
	rc4.InitKey(key)
	c := rc4.s[rc4.j] + rc4.s[rc4.i]
	rollover := int(1024*128) + int(rc4.s[rc4.j])*256 + int(rc4.s[rc4.s[rc4.s[rc4.s[c]]]])
	dummy := make([]byte, rollover)
	rc4.XorInplace(dummy) // roll forward
	rc4.XorInplace(data)
}
