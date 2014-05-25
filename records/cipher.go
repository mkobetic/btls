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
	Cipher        okapi.CipherConstructor
	CipherKeySize int
	MAC           okapi.HashConstructor
	MACKeySize    int
}

func NewCipher(spec CipherSpec, version ProtocolVersion, key, iv, macKey []byte, encrypt bool) Cipher {
	cipher := spec.Cipher(key, iv, encrypt)
	if version == SSL30 {
		mac := spec.MAC(macKey)
		if cipher.kind == stream {
			return SSL30StreamCipher{cipher, mac}
		} else {
			return SSL30BlockCipher{cipher, mac}
		}
	}
	mac := spec.MAC(macKey)
	switch spec.kind {
	case stream:
		return StreamCipher{cipher, mac}
	case block:
		if version == TLS10 {
			return TLS10BlockCipher{cipher, mac}
		}
		BlockCipher{cipher, mac}
	case aead:
		return AEADCipher{cipher, mac}
	}
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

// SSL30 uses custom MAC and implicit IVs
type SSL30StreamCipher struct{}
type SSL30BlockCipher struct{}

// TLS uses HMAC and explicit IVs (except TLS10)
type StreamCipher struct{}
type TLS10BlockCipher struct{} // still uses implicit IVs
type BlockCipher struct{}
type AEADCipher struct{}
