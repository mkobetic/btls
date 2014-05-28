package records

import (
	"bytes"
	"github.com/mkobetic/okapi"
)

// SSL30 uses custom MAC and implicit IVs
type SSL30StreamCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *SSL30StreamCipher) Open(payload, buffer []byte) (int, error) {
	return 0, nil
}
func (c *SSL30StreamCipher) Seal(payload, buffer []byte) (int, error) {
	return 0, nil
}

func (c *SSL30StreamCipher) Close() {
	c.cipher.Close()
	c.mac.Close()
}

type SSL30BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *SSL30BlockCipher) Open(payload, buffer []byte) (int, error) {
	return 0, nil
}
func (c *SSL30BlockCipher) Seal(payload, buffer []byte) (int, error) {
	return 0, nil
}

func (c *SSL30BlockCipher) Close() {
	c.cipher.Close()
	c.mac.Close()
}

type SSL30MAC struct {
	pad1   []byte
	pad2   []byte
	digest []byte
	hash   okapi.Hash
}

var (
	PAD1 = bytes.Repeat([]byte{0x36}, 8)
	PAD2 = bytes.Repeat([]byte{0x5c}, 8)
)

func NewSSL30MAC(hs okapi.HashSpec, key []byte) okapi.Hash {
	hash := hs.New()
	var pad1, pad2 []byte
	var size int
	if hash.Size() == 16 {
		size = len(key) + 48 // MD5
	} else {
		size = len(key) + 40 // SHA
	}
	pad1 = make([]byte, size)
	pad2 = make([]byte, size, size+hash.Size())
	copy(pad1, key)
	fill(pad1[len(key):], PAD1)
	copy(pad2, key)
	fill(pad2[len(key):], PAD2)
	hash.Write(pad1)
	return &SSL30MAC{pad1: pad1, pad2: pad2, hash: hash}
}

func (m *SSL30MAC) Write(b []byte) (int, error) {
	return m.hash.Write(b)
}

func (m *SSL30MAC) Digest() []byte {
	if m.digest != nil {
		return m.digest
	}
	inner := append(m.pad2, m.hash.Digest()...)
	m.hash.Reset()
	m.hash.Write(inner)
	m.digest = m.hash.Digest()
	return m.digest
}

func (m *SSL30MAC) Size() int {
	return m.hash.Size()
}

func (m *SSL30MAC) BlockSize() int {
	return m.hash.BlockSize()
}

func (m *SSL30MAC) Clone() okapi.Hash {
	panic("Not needed!")
}

func (m *SSL30MAC) Reset() {
	m.digest = nil
	m.hash.Reset()
	m.hash.Write(m.pad1)
}

func (m *SSL30MAC) Close() {
	if m.hash == nil {
		return
	}
	defer m.hash.Close()
	m.hash = nil
}

func fill(b, pad []byte) {
	for len(b) > 0 {
		b = b[copy(b, pad):]
	}
}
