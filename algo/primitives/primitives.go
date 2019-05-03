package primitives

// this package must not import any dependencies

func XorInplace(dst []byte, gamma []byte, sz int) {
	for i := 0; i < sz; i++ {
		dst[i] ^= gamma[i]
	}
}

func Min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func ReverseInt(a []int) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
		i++
		j--
	}
}

func ReverseBytes(a []byte) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
		i++
		j--
	}
}

func Substitute(s []byte, prev byte, ersatz byte) {
	for i := 0; i < len(s); i++ {
		if s[i] == prev {
			s[i] = ersatz
		}
	}
}

func IsDeepNotEqual(a []byte, b []byte, sz int) bool {
	const block = 5
	for i := 0; i < sz - block; i++ {
		ok := isBlockNotEqual(a, b, i, block)
		if !ok {
			//fmt.Printf("%d [%x] [%x]\n[%x]\n[%x]\n", i, a[i:i+block], b[i:i+block], a, b)
			return false
		}
	}
	return true
}

func isBlockNotEqual(a []byte, b []byte, off int, block int) bool {
	for i := off; i < off + block; i++ {
		if a[i] != b[i] {
			return true
		}
	}
	return false
}

func IsPowerOfTwo(i uint64) bool {
	j := i - 1
	x := i & j
	return x == 0
}

func FindNextPowerOfTwo(n int) int {
	x := 2
	for i := 0; i < 32; i++ {
		if x >= n {
			return x
		} else {
			x *= 2
		}
	}
	return 0
}
