package records

import (
	"github.com/mkobetic/okapi"
)

type Cipher interface {
	Open(payload, buffer []byte) (int, error)
	Seal(payload, buffer []byte) (int, error)
}

type CipherKind int

const (
	stream CipherKind = iota
	block
	aead
)

type CipherSpec struct {
	kind          CipherKind
	Cipher        okapi.CipherSpec
	CipherKeySize int
	MAC           okapi.HashSpec
	MACKeySize    int
}

func NewCipher(spec CipherSpec, version ProtocolVersion, key, iv, macKey []byte, encrypt bool) Cipher {
	cipher := spec.Cipher.New(key, iv, encrypt)
	if version == SSL30 {
		mac := NewSSL30MAC(spec.MAC, macKey)
		if spec.kind == stream {
			return &SSL30StreamCipher{cipher, mac}
		} else {
			return &SSL30BlockCipher{cipher, mac}
		}
	}
	mac := okapi.HMAC.New(spec.MAC, macKey)
	switch spec.kind {
	case stream:
		return &StreamCipher{cipher, mac}
	case block:
		if version == TLS10 {
			return &TLS10BlockCipher{cipher, mac}
		}
		return &BlockCipher{cipher, mac}
	case aead:
		return &AEADCipher{cipher, mac}
	}
	return nil
}

var (
	NULL_NULL          = CipherSpec{stream, nil, 0, nil, 0}
	NULL_MD5           = CipherSpec{stream, nil, 0, okapi.MD5, 16}
	NULL_SHA           = CipherSpec{stream, nil, 0, okapi.SHA1, 20}
	NULL_SHA256        = CipherSpec{stream, nil, 0, okapi.SHA256, 32}
	RC4_128_MD5        = CipherSpec{stream, okapi.RC4, 16, okapi.MD5, 16}
	RC4_128_SHA        = CipherSpec{stream, okapi.RC4, 16, okapi.SHA1, 20}
	DES_EDE_CBC_SHA    = CipherSpec{block, okapi.DES3_CBC, 24, okapi.SHA1, 20}
	AES_128_CBC_SHA    = CipherSpec{block, okapi.AES_CBC, 16, okapi.SHA1, 20}
	AES_128_CBC_SHA256 = CipherSpec{block, okapi.AES_CBC, 16, okapi.SHA256, 32}
	AES_256_CBC_SHA    = CipherSpec{block, okapi.AES_CBC, 32, okapi.SHA1, 20}
	AES_256_CBC_SHA256 = CipherSpec{block, okapi.AES_CBC, 32, okapi.SHA256, 32}
)

// TLS uses HMAC and explicit IVs (except TLS10)
type StreamCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *StreamCipher) Open(payload, buffer []byte) (int, error) {
	return 0, nil
}
func (c *StreamCipher) Seal(payload, buffer []byte) (int, error) {
	return 0, nil
}

// TLS 1.0 still uses implicit IVs
type TLS10BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *TLS10BlockCipher) Open(payload, buffer []byte) (int, error) {
	return 0, nil
}
func (c *TLS10BlockCipher) Seal(payload, buffer []byte) (int, error) {
	return 0, nil
}

type BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *BlockCipher) Open(payload, buffer []byte) (int, error) {
	return 0, nil
}
func (c *BlockCipher) Seal(payload, buffer []byte) (int, error) {
	return 0, nil
}

type AEADCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *AEADCipher) Open(payload, buffer []byte) (int, error) {
	return 0, nil
}
func (c *AEADCipher) Seal(payload, buffer []byte) (int, error) {
	return 0, nil
}
