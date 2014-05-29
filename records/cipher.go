package records

import (
	"crypto/subtle"
	"encoding/binary"
	"github.com/mkobetic/okapi"
)

type Cipher interface {
	Open(buffer []byte, size int) (int, error)
	Seal(buffer []byte, size int) (int, error)
	Close()
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
	var cipher okapi.Cipher
	var mac okapi.Hash
	if spec.Cipher != nil {
		cipher = spec.Cipher.New(key, iv, encrypt)
	}
	if version == SSL30 {
		if spec.MAC != nil {
			mac = NewSSL30MAC(spec.MAC, macKey)
		}
		if spec.kind == stream {
			return &SSL30StreamCipher{cipher: cipher, mac: mac}
		} else {
			return &SSL30BlockCipher{cipher: cipher, mac: mac}
		}
	}
	if spec.MAC != nil {
		mac = okapi.HMAC.New(spec.MAC, macKey)
	}
	switch spec.kind {
	case stream:
		return &StreamCipher{cipher: cipher, mac: mac}
	case block:
		if version == TLS10 {
			return &TLS10BlockCipher{cipher: cipher, mac: mac}
		}
		return &BlockCipher{cipher: cipher, mac: mac}
	case aead:
		return &AEADCipher{cipher: cipher, mac: mac}
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

func (c *StreamCipher) Open(buffer []byte, size int) (int, error) {
	if c.cipher != nil {
		ciphertext := buffer[BufferHeaderSize:]
		ins, outs := c.cipher.Update(ciphertext[:size], ciphertext)
		_assert(ins == size, "cipher input size %d, expected %d", ins, size)
		_assert(outs == size, "cipher output size %d, expected %d", outs, size)
	}
	if c.mac != nil {
		size -= c.mac.Size()
		length := buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
		binary.BigEndian.PutUint16(length, uint16(size))
		c.mac.Write(buffer[:BufferHeaderSize+size])
		buffer = buffer[BufferHeaderSize+size:]
		ok := subtle.ConstantTimeCompare(buffer[:c.mac.Size()], c.mac.Digest()) == 1
		c.mac.Reset()
		if !ok {
			return size, InvalidRecordMAC
		}
	}
	return size, nil
}

func (c *StreamCipher) Seal(buffer []byte, size int) (int, error) {
	length := buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
	binary.BigEndian.PutUint16(length, uint16(size))
	if c.mac != nil {
		c.mac.Write(buffer[:BufferHeaderSize+size])
		size += copy(buffer[BufferHeaderSize+size:], c.mac.Digest())
		c.mac.Reset()
		binary.BigEndian.PutUint16(length, uint16(size))
	}
	buffer = buffer[BufferHeaderSize:]
	if c.cipher != nil {
		ins, outs := c.cipher.Update(buffer[:size], buffer)
		_assert(ins == size, "cipher input size %d, expected %d", ins, size)
		_assert(outs == size, "cipher output size %d, expected %d", outs, size)
	}
	return size, nil
}

func (c *StreamCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
}

// TLS 1.0 still uses implicit IVs
type TLS10BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *TLS10BlockCipher) Open(buffer []byte, size int) (int, error) {
	return 0, nil
}
func (c *TLS10BlockCipher) Seal(buffer []byte, size int) (int, error) {
	return 0, nil
}

func (c *TLS10BlockCipher) Close() {
	c.cipher.Close()
	c.mac.Close()
}

type BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *BlockCipher) Open(buffer []byte, size int) (int, error) {
	return 0, nil
}
func (c *BlockCipher) Seal(buffer []byte, size int) (int, error) {
	return 0, nil
}

func (c *BlockCipher) Close() {
	c.cipher.Close()
	c.mac.Close()
}

type AEADCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *AEADCipher) Open(buffer []byte, size int) (int, error) {
	return 0, nil
}

func (c *AEADCipher) Seal(buffer []byte, size int) (int, error) {
	return 0, nil
}

func (c *AEADCipher) Close() {
	c.cipher.Close()
	c.mac.Close()
}
