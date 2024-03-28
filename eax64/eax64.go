package eax64

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/pedroalbanese/eax/byteutil"
)

const (
	defaultTagSize   = 8 // Tag size for 64-bit blocks
	defaultNonceSize = 16 // Nonce size (unchanged)
)

type eax64 struct {
	block     cipher.Block
	tagSize   int
	nonceSize int
}

// NonceSize returns the size of the nonce.
func (e *eax64) NonceSize() int {
	return e.nonceSize
}

// Overhead returns the tag size.
func (e *eax64) Overhead() int {
	return e.tagSize
}

// NewEAX returns a new EAX instance.
func NewEAX(block cipher.Block) (cipher.AEAD, error) {
	return NewEAXWithNonceAndTagSize(block, defaultNonceSize, defaultTagSize)
}

// NewEAXWithNonceAndTagSize returns a new EAX instance with custom nonce and tag sizes.
func NewEAXWithNonceAndTagSize(block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize < 1 {
		return nil, eax64Error("Cannot initialize EAX with nonceSize = 0")
	}
	if tagSize > block.BlockSize() {
		return nil, eax64Error("Custom tag length exceeds blocksize")
	}
	return &eax64{
		block:     block,
		tagSize:   tagSize,
		nonceSize: nonceSize,
	}, nil
}

// Seal encrypts and authenticates plaintext with associated data, returning the ciphertext.
func (e *eax64) Seal(dst, nonce, plaintext, adata []byte) []byte {
	if len(nonce) > e.nonceSize {
		panic("crypto/eax64: Nonce too long for this instance")
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
func (e *eax64) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(nonce) > e.nonceSize {
		panic("crypto/eax64: Nonce too long for this instance")
	}
	if len(ciphertext) < e.tagSize {
		return nil, eax64Error("Ciphertext shorter than tag length")
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
		return nil, eax64Error("Tag authentication failed")
	}

	ret, out := SliceForAppend(dst, len(ciphertext))
	ctr := cipher.NewCTR(e.block, omacNonce)
	ctr.XORKeyStream(out, ciphertext[:sep])

	return ret[:sep], nil
}

// omacT calculates the OMAC for a given type.
func (e *eax64) omacT(t byte, plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	byteT := make([]byte, blockSize)
	byteT[blockSize-1] = t
	concat := append(byteT, plaintext...)
	return e.omac(concat)
}

// omac calculates the OMAC for a given plaintext.
func (e *eax64) omac(plaintext []byte) []byte {
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
func (e *eax64) pad(plaintext, B, P []byte) []byte {
	blockSize := e.block.BlockSize()
	if len(plaintext) != 0 && len(plaintext)%blockSize == 0 {
		return RightXor(plaintext, B)
	}

	ending := make([]byte, blockSize-len(plaintext)%blockSize)
	ending[0] = 0x80
	padded := append(plaintext, ending...)
	return RightXor(padded, P)
}

// eax64Error creates a new EAX error.
func eax64Error(err string) error {
	return errors.New("crypto/eax64: " + err)
}
