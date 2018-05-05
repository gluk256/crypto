package rcx

const rc4sz = 256

type RC4 struct {
	s [rc4sz]byte
	i, j byte
}

func (c *RC4) InitKey(key []byte) {
	for i := 0; i < rc4sz; i++ {
		c.s[i] = byte(i)
	}

	var j byte
	for i := 0; i < rc4sz; i++ {
		j += c.s[i] + key[i % len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}

	c.i = 0
	c.j = 0
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
