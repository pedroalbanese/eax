package eax

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/pedroalbanese/eax/byteutil"
)

const (
	defaultTagSize   = 32
	defaultNonceSize = 16
)

type eax struct {
	block     cipher.Block
	tagSize   int
	nonceSize int
}

func (e *eax) NonceSize() int {
	return e.nonceSize
}

func (e *eax) Overhead() int {
	return e.tagSize
}

func NewEAX(block cipher.Block) (cipher.AEAD, error) {
	return NewEAXWithNonceAndTagSize(block, defaultNonceSize, defaultTagSize)
}

func NewEAXWithNonceAndTagSize(
	block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize < 1 {
		return nil, eaxError("Cannot initialize EAX with nonceSize = 0")
	}
	if tagSize > block.BlockSize() {
		return nil, eaxError("Custom tag length exceeds blocksize")
	}
	return &eax{
		block:     block,
		tagSize:   tagSize,
		nonceSize: nonceSize,
	}, nil
}

func (e *eax) Seal(dst, nonce, plaintext, adata []byte) []byte {
	if len(nonce) > e.nonceSize {
		panic("crypto/eax: Nonce too long for this instance")
	}
	ret, out := byteutil.SliceForAppend(dst, len(plaintext) + e.tagSize)
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

func (e* eax) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(nonce) > e.nonceSize {
		panic("crypto/eax: Nonce too long for this instance")
	}
	if len(ciphertext) < e.tagSize {
		return nil, eaxError("Ciphertext shorter than tag length")
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
		return nil, eaxError("Tag authentication failed")
	}

	ret, out := byteutil.SliceForAppend(dst, len(ciphertext))
	ctr := cipher.NewCTR(e.block, omacNonce)
	ctr.XORKeyStream(out, ciphertext[:sep])

	return ret[:sep], nil
}

func (e *eax) omacT(t byte, plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	byteT := make([]byte, blockSize)
	byteT[blockSize-1] = t
	concat := append(byteT, plaintext...)
	return e.omac(concat)
}

func (e *eax) omac(plaintext []byte) []byte {
	blockSize := e.block.BlockSize()
	L := make([]byte, blockSize)
	e.block.Encrypt(L, L)
	B := byteutil.GfnDouble(L, 32)
	P := byteutil.GfnDouble(B, 32)

	cbc := cipher.NewCBCEncrypter(e.block, make([]byte, blockSize))
	padded := e.pad(plaintext, B, P)
	cbcCiphertext := make([]byte, len(padded))
	cbc.CryptBlocks(cbcCiphertext, padded)

	return cbcCiphertext[len(cbcCiphertext)-blockSize:]
}

func (e *eax) pad(plaintext, B, P []byte) []byte {
	blockSize := e.block.BlockSize()
	if len(plaintext) != 0 && len(plaintext)%blockSize == 0 {
		return byteutil.RightXor(plaintext, B)
	}

	ending := make([]byte, blockSize-len(plaintext)%blockSize)
	ending[0] = 0x80
	padded := append(plaintext, ending...)
	return byteutil.RightXor(padded, P)
}

func eaxError(err string) error {
	return errors.New("crypto/eax: " + err)
}