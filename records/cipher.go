package records

import (
	"crypto/subtle"
	"encoding/binary"
	"github.com/mkobetic/okapi"
)

type CipherKind int

const (
	stream CipherKind = iota
	block
	aead
)

type CipherSpec struct {
	kind            CipherKind
	Cipher          okapi.CipherSpec
	CipherKeySize   int
	CipherBlockSize int
	MAC             okapi.HashSpec
	MACKeySize      int
}

var (
	NULL_NULL          = CipherSpec{stream, nil, 0, 0, nil, 0}
	NULL_MD5           = CipherSpec{stream, nil, 0, 0, okapi.MD5, 16}
	NULL_SHA           = CipherSpec{stream, nil, 0, 0, okapi.SHA1, 20}
	NULL_SHA256        = CipherSpec{stream, nil, 0, 0, okapi.SHA256, 32}
	RC4_128_MD5        = CipherSpec{stream, okapi.RC4, 16, 1, okapi.MD5, 16}
	RC4_128_SHA        = CipherSpec{stream, okapi.RC4, 16, 1, okapi.SHA1, 20}
	DES_EDE_CBC_SHA    = CipherSpec{block, okapi.DES3_CBC, 24, 8, okapi.SHA1, 20}
	AES_128_CBC_SHA    = CipherSpec{block, okapi.AES_CBC, 16, 16, okapi.SHA1, 20}
	AES_128_CBC_SHA256 = CipherSpec{block, okapi.AES_CBC, 16, 16, okapi.SHA256, 32}
	AES_256_CBC_SHA    = CipherSpec{block, okapi.AES_CBC, 32, 16, okapi.SHA1, 20}
	AES_256_CBC_SHA256 = CipherSpec{block, okapi.AES_CBC, 32, 16, okapi.SHA256, 32}
)

type Cipher interface {
	Open(buffer []byte, size int) (int, error)
	Seal(buffer []byte, size int) (int, error)
	Close()
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

// TLS uses HMAC and explicit IVs (except TLS10)
type StreamCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *StreamCipher) Open(buffer []byte, size int) (int, error) {
	decrypt(c.cipher, buffer, size)
	return verify(c.mac, buffer, size)
}

func (c *StreamCipher) Seal(buffer []byte, size int) (int, error) {
	size = sign(c.mac, buffer, size)
	encrypt(c.cipher, buffer, size)
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

// TLS 1.0 needs specialized block cipher because it still uses implicit IVs
type TLS10BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *TLS10BlockCipher) Seal(buffer []byte, size int) (int, error) {
	size = sign(c.mac, buffer, size)
	size = addPadding(c.cipher, buffer, size)
	encrypt(c.cipher, buffer, size)
	return size, nil
}

func (c *TLS10BlockCipher) Open(buffer []byte, size int) (int, error) {
	decrypt(c.cipher, buffer, size)
	size = removePadding(c.cipher, buffer, size)
	return verify(c.mac, buffer, size)
}

func (c *TLS10BlockCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
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
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
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
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
}

func encrypt(cipher okapi.Cipher, buffer []byte, size int) {
	if cipher == nil {
		return
	}
	// Encrypt everything after the header.
	buffer = buffer[BufferHeaderSize:]
	ins, outs := cipher.Update(buffer[:size], buffer)
	_assert(ins == size, "cipher input size %d, expected %d", ins, size)
	_assert(outs == size, "cipher output size %d, expected %d", outs, size)
}

func decrypt(cipher okapi.Cipher, buffer []byte, size int) {
	if cipher == nil {
		return
	}
	// Decrypt everything after the header.
	ciphertext := buffer[BufferHeaderSize:]
	ins, outs := cipher.Update(ciphertext[:size], ciphertext)
	_assert(ins == size, "cipher input size %d, expected %d", ins, size)
	_assert(outs == size, "cipher output size %d, expected %d", outs, size)
}

func addPadding(cipher okapi.Cipher, buffer []byte, size int) int {
	// TODO: Add randomized padding length
	return addPaddingSSL30(cipher, buffer, size)
}

func removePadding(cipher okapi.Cipher, buffer []byte, size int) int {
	var pad = int(buffer[BufferHeaderSize+size-1])
	return size - 1 - pad
}

func sign(mac okapi.Hash, buffer []byte, size int) int {
	// Update the length field in the header with the data size.
	lengthHeader := buffer[BufferHeaderSize-HeaderSize+3:][:2]
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	if mac == nil {
		return size
	}
	// Hash whole buffer (including the seq_num and record header).
	mac.Write(buffer[:BufferHeaderSize+size])
	// Append the digest at the end.
	size += copy(buffer[BufferHeaderSize+size:], mac.Digest())
	mac.Reset()
	// Update the length field in the header to include the digest
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	return size
}

func verify(mac okapi.Hash, buffer []byte, size int) (int, error) {
	if mac == nil {
		return size, nil
	}
	size -= mac.Size()
	// Adjust the length field in the header to exclude the record digest,
	// so that we can feed the buffer directly into to the MAC function.
	lengthHeader := buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	mac.Write(buffer[:BufferHeaderSize+size])
	buffer = buffer[BufferHeaderSize+size:]
	// Check that the computed digest matches the received digest.
	ok := subtle.ConstantTimeCompare(buffer[:mac.Size()], mac.Digest()) == 1
	mac.Reset()
	if !ok {
		return size, InvalidRecordMAC
	}
	return size, nil
}
