package rcx

const rc4sz = 256

type RC4 struct {
	s [rc4sz]byte
	i byte
}

func (c *RC4) InitKey(key []byte) {
	c.i = 0
	for i := 0; i < rc4sz; i++ {
		c.s[i] = byte(i)
	}

	var j byte
	for i := 0; i < rc4sz; i++ {
		j += c.s[i] + key[i % len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
}

func (c *RC4) XorInplace(data []byte) {
	var j byte
	for n := 0; n < len(data); n++ {
		c.i++
		j += c.s[c.i]
		c.s[c.i], c.s[j] = c.s[j], c.s[c.i]

		x := c.s[c.i] + c.s[j]
		data[n] ^= c.s[x]
	}
}
