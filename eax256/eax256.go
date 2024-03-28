package eax256

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	defaultTagSize   = 32 // Tag size for 256-bit blocks
	defaultNonceSize = 16 // Nonce size (unchanged)
)

type eax256 struct {
	block     cipher.Block
	tagSize   int
	nonceSize int
}

// NonceSize returns the size of the nonce.
func (e *eax256) NonceSize() int {
	return e.nonceSize
}

// Overhead returns the tag size.
func (e *eax256) Overhead() int {
	return e.tagSize
}

// NewEAX returns a new EAX instance.
func NewEAX(block cipher.Block) (cipher.AEAD, error) {
	return NewEAXWithNonceAndTagSize(block, defaultNonceSize, defaultTagSize)
}

// NewEAXWithNonceAndTagSize returns a new EAX instance with custom nonce and tag sizes.
func NewEAXWithNonceAndTagSize(block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize < 1 {
		return nil, eax256Error("Cannot initialize EAX with nonceSize = 0")
	}
	if tagSize > block.BlockSize() {
		return nil, eax256Error("Custom tag length exceeds blocksize")
	}
	return &eax256{
		block:     block,
		tagSize:   tagSize,
		nonceSize: nonceSize,
	}, nil
}

// Seal encrypts and authenticates plaintext with associated data, returning the ciphertext.
func (e *eax256) Seal(dst, nonce, plaintext, adata []byte) []byte {
	if len(nonce) > e.nonceSize {
		panic("crypto/eax256: Nonce too long for this instance")
	}
	ret, out := SliceForAppend(dst, len(plaintext)+e.tagSize)
	omacNonce := e.omacT(0, nonce)
	omacAdata := e.omacT(1, adata)

	ctr := cipher.NewCTR(e.block, omacNonce)
	ciphertextData := out[:len(plaintext)]
	ctr.XORKeyStream(ciphertextData, plaintext)

	omacCiphertext := e.omacT(2, ciphertextData)

	tag := out[len(plaintext):]
	for i := 0; i < e.tagSize; i++ {
		tag[i] = omacCiphertext[i] ^ omacNonce[i] ^ omacAdata[i]
	}
	return ret
}

// Open decrypts and authenticates ciphertext with associated data, returning the plaintext.
func (e *eax256) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(nonce) > e.nonceSize {
		panic("crypto/eax256: Nonce too long for this instance")
	}
	if len(ciphertext) < e.tagSize {
		return nil, eax256Error("Ciphertext shorter than tag length")
	}
	sep := len(ciphertext) - e.tagSize

	omacNonce := e.omacT(0, nonce)
	omacAdata := e.omacT(1, adata)
	omacCiphertext := e.omacT(2, ciphertext[:sep])

	tag := make([]byte, e.tagSize)
	for i := 0; i < e.tagSize; i++ {
		tag[i] = omacCiphertext[i] ^ omacNonce[i] ^ omacAdata[i]
	}

	if subtle.ConstantTimeCompare(ciphertext[sep:], tag) != 1 {
		return nil, eax256Error("Tag authentication failed")
	}

	ret, out := SliceForAppend(dst, len(ciphertext))
	ctr := cipher.NewCTR(e.block, omacNonce)
	ctr.XORKeyStream(out, ciphertext[:sep])

	return ret[:sep], nil
}

// omacT calculates the OMAC for a given type.
func (e *eax256) omacT(t byte, plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	byteT := make([]byte, blockSize)
	byteT[blockSize-1] = t
	concat := append(byteT, plaintext...)
	return e.omac(concat)
}

// omac calculates the OMAC for a given plaintext.
func (e *eax256) omac(plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	L := make([]byte, blockSize)
	e.block.Encrypt(L, L)
	B := GfnDouble(L)
	P := GfnDouble(B)

	cbc := cipher.NewCBCEncrypter(e.block, make([]byte, blockSize))
	padded := e.pad(plaintext, B, P)
	cbcCiphertext := make([]byte, len(padded))
	cbc.CryptBlocks(cbcCiphertext, padded)

	return cbcCiphertext[len(cbcCiphertext)-blockSize:]
}

// pad pads the plaintext using the EAX algorithm.
func (e *eax256) pad(plaintext, B, P []byte) []byte {
	blockSize := e.block.BlockSize()
	if len(plaintext) != 0 && len(plaintext)%blockSize == 0 {
		return RightXor(plaintext, B)
	}

	ending := make([]byte, blockSize-len(plaintext)%blockSize)
	ending[0] = 0x80
	padded := append(plaintext, ending...)
	return RightXor(padded, P)
}

// eax256Error creates a new EAX error.
func eax256Error(err string) error {
	return errors.New("crypto/eax256: " + err)
}

func GfnDouble(input []byte) []byte {
	if len(input) != 32 {
		panic("Doubling in GFn only implemented for n = 256")
	}
	shifted := ShiftBytesLeft(input)
	shifted[31] ^= ((input[0] >> 7) * 0x87)
	return shifted
}

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