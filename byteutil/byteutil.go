package byteutil

func GfnDouble(input []byte, blockSize int) []byte {
	switch blockSize {
	case 8: // 64 bits
		if len(input) != 8 {
			panic("Doubling in GFn only implemented for n = 64")
		}
		shifted := ShiftBytesLeft(input)
		shifted[7] ^= ((input[0] >> 7) * 0x87)
		return shifted
	case 12: // 96 bits (Curupira-specific implementation)
		if len(input) != 12 {
			panic("Doubling in GFn only implemented for n = 96")
		}
		shifted := ShiftBytesLeft(input)
		shifted[11] ^= ((input[0] >> 7) * 0x87)
		return shifted
	case 16: // 128 bits
		if len(input) != 16 {
			panic("Doubling in GFn only implemented for n = 128")
		}
		shifted := ShiftBytesLeft(input)
		shifted[15] ^= ((input[0] >> 7) * 0x87)
		return shifted
	case 32: // 256 bits
		if len(input) != 32 {
			panic("Doubling in GFn only implemented for n = 256")
		}
		shifted := ShiftBytesLeft(input)
		shifted[31] ^= ((input[0] >> 7) * 0x87)
		return shifted
	case 64: // 512 bits
		if len(input) != 64 {
			panic("Doubling in GFn only implemented for n = 512")
		}
		shifted := ShiftBytesLeft(input)
		shifted[63] ^= ((input[0] >> 7) * 0x87)
		return shifted
	case 128: // 1024 bits
		if len(input) != 128 {
			panic("Doubling in GFn only implemented for n = 512")
		}
		shifted := ShiftBytesLeft(input)
		shifted[127] ^= ((input[0] >> 7) * 0x87)
		return shifted
	default:
		panic("Invalid block size")
	}
}

/*
func GfnDouble(input []byte) []byte {
	if len(input) != 16 {
		panic("Doubling in GFn only implemented for n = 128")
	}
	shifted := ShiftBytesLeft(input)
	shifted[15] ^= ((input[0] >> 7) * 0x87)
	return shifted
}
*/

func ShiftBytesLeft(x []byte) []byte {
	l := len(x)
	dst := make([]byte, l)
	for i := 0; i < l-1; i++ {
		dst[i] = (x[i] << 1) | (x[i+1] >> 7)
	}
	dst[l-1] = x[l-1] << 1
	return dst
}

func ShiftNBytesLeft(dst, x []byte, n int) {
	copy(dst, x[n/8:])

	bits := uint(n % 8)
	l := len(dst)
	for i := 0; i < l-1; i++ {
		dst[i] = (dst[i] << bits) | (dst[i+1] >> uint(8-bits))
	}
	dst[l-1] = dst[l-1] << bits

	dst = append(dst, make([]byte, n/8)...)
}

func XorBytesMut(X, Y []byte) {
	for i := 0; i < len(X); i++ {
		X[i] ^= Y[i]
	}
}

func XorBytes(Z, X, Y []byte) {
	for i := 0; i < len(X); i++ {
		Z[i] = X[i] ^ Y[i]
	}
}

func RightXor(X, Y []byte) []byte {
	offset := len(X) - len(Y)
	xored := make([]byte, len(X))
	copy(xored, X)
	for i := 0; i < len(Y); i++ {
		xored[offset+i] ^= Y[i]
	}
	return xored
}

func SliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
