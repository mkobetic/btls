package records

import (
	"crypto/subtle"
	"encoding/binary"
	"io"

	"github.com/mkobetic/okapi"
)

// CipherKind represents different Cipher types as defined by the protocol specification.
type CipherKind int

const (
	stream CipherKind = iota
	block
	aead
)

// Random defines an interface for a secure random generator.
type Random interface {
	io.Reader
	Close()
}

// CipherSpec describes specific combination of encryption and MAC algorithms.
// Legal combinations are defined by the protocol specification and other associated RFCs.
type CipherSpec interface {
	// New creates a Cipher using provided parameters.
	New(version ProtocolVersion, key, iv, macKey []byte, encrypt bool, random Random) Cipher
}

// OkapiCipherSpec implements CipherSpec using okapi package
type OkapiCipherSpec struct {
	kind            CipherKind
	Cipher          okapi.CipherSpec
	CipherKeySize   int
	CipherBlockSize int
	MAC             okapi.HashSpec
	MACKeySize      int
}

// Standard supported CipherSpecs
var (
	NULL_NULL          = &OkapiCipherSpec{stream, nil, 0, 0, nil, 0}
	NULL_MD5           = &OkapiCipherSpec{stream, nil, 0, 0, okapi.MD5, 16}
	NULL_SHA           = &OkapiCipherSpec{stream, nil, 0, 0, okapi.SHA1, 20}
	NULL_SHA256        = &OkapiCipherSpec{stream, nil, 0, 0, okapi.SHA256, 32}
	RC4_128_MD5        = &OkapiCipherSpec{stream, okapi.RC4, 16, 1, okapi.MD5, 16}
	RC4_128_SHA        = &OkapiCipherSpec{stream, okapi.RC4, 16, 1, okapi.SHA1, 20}
	DES_EDE_CBC_SHA    = &OkapiCipherSpec{block, okapi.DES3_CBC, 24, 8, okapi.SHA1, 20}
	AES_128_CBC_SHA    = &OkapiCipherSpec{block, okapi.AES_CBC, 16, 16, okapi.SHA1, 20}
	AES_128_CBC_SHA256 = &OkapiCipherSpec{block, okapi.AES_CBC, 16, 16, okapi.SHA256, 32}
	AES_256_CBC_SHA    = &OkapiCipherSpec{block, okapi.AES_CBC, 32, 16, okapi.SHA1, 20}
	AES_256_CBC_SHA256 = &OkapiCipherSpec{block, okapi.AES_CBC, 32, 16, okapi.SHA256, 32}
)

// Cipher defines the interface of SSL/TLS record ciphers as defined by the protocol specification.
type Cipher interface {
	// Open decrypts and verifies integrity of an incoming record.
	// Returns slice containing the unsealed record contents or error.
	Open(buffer []byte, size int) ([]byte, error)
	// Seal encrypts and signs an outgoing record.
	// Returns the slice containing the sealed record or error.
	Seal(buffer []byte, size int) ([]byte, error)
	// Close securely releases associated resources.
	// It MUST be called before a Cipher instance is discarded.
	Close()
	// SealedRecordOffset specifies the expected start of a sealed record in a buffer.
	// For most Ciphers that is PayloadOffset-HeaderSize, but for block cipher in TLS1.1
	// and later it is further offset by BlockSize to accommodate the explict IV
	// inserted between the header and the payload.
	SealedRecordOffset() int
}

// New creates and configures an appropriate Cipher implemetation for the provided security parameters.
func (spec *OkapiCipherSpec) New(version ProtocolVersion, key, iv, macKey []byte, encrypt bool, random Random) Cipher {
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
	// TLS uses HMAC and explicit IVs (except TLS10)
	if spec.MAC != nil {
		mac = okapi.HMAC.New(spec.MAC, macKey)
	}
	switch spec.kind {
	case stream:
		return &StreamCipher{cipher: cipher, mac: mac}
	case block:
		if version == TLS10 {
			return &TLS10BlockCipher{cipher: cipher, mac: mac, random: random}
		}
		return &BlockCipher{cipher: cipher, mac: mac, random: random}
	case aead:
		return &AEADCipher{cipher: cipher, mac: mac}
	}
	return nil
}

var (
	// The default Random used by Ciphers if one is not provided.
	DefaultRandom = okapi.DefaultRandom.New()
)

// StreamCipher implements TLS stream cipher. It is used for TLS 1.0, 1.1, and 1.2.
type StreamCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *StreamCipher) Open(buffer []byte, size int) ([]byte, error) {
	decrypt(c.cipher, buffer, size, 0)
	return verify(c.mac, buffer, size)
}

func (c *StreamCipher) Seal(buffer []byte, size int) ([]byte, error) {
	size = sign(c.mac, buffer, size)
	return encrypt(c.cipher, buffer, size, 0)
}

func (c *StreamCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
}

func (c *StreamCipher) SealedRecordOffset() int { return PayloadOffset - HeaderSize }

// TLS 1.0 needs specialized block cipher because it still uses implicit IVs.
type TLS10BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
	random okapi.Random
}

func (c *TLS10BlockCipher) Seal(buffer []byte, size int) ([]byte, error) {
	size = sign(c.mac, buffer, size)
	size = addPadding(c.cipher, buffer, size, 0, c.random)
	return encrypt(c.cipher, buffer, size, 0)
}

func (c *TLS10BlockCipher) Open(buffer []byte, size int) ([]byte, error) {
	decrypt(c.cipher, buffer, size, 0)
	size = removePadding(c.cipher, buffer, size, 0)
	return verify(c.mac, buffer, size)
}

func (c *TLS10BlockCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
	if c.random != nil {
		c.random.Close()
	}
}

func (c *TLS10BlockCipher) SealedRecordOffset() int { return PayloadOffset - HeaderSize }

// BlockCipher implements TLS block cipher, used by TLS 1.1 and 1.2.
type BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
	random okapi.Random
}

func (c *BlockCipher) Seal(buffer []byte, size int) ([]byte, error) {
	size = sign(c.mac, buffer, size)
	var ivSize = c.cipher.BlockSize()
	size = insertIV(buffer, size, ivSize, c.random)
	size = addPadding(c.cipher, buffer, size, ivSize, c.random)
	return encrypt(c.cipher, buffer, size, ivSize)
}

func (c *BlockCipher) Open(buffer []byte, size int) ([]byte, error) {
	var ivSize = c.cipher.BlockSize()
	decrypt(c.cipher, buffer, size, ivSize)
	size = removePadding(c.cipher, buffer, size, ivSize)
	size = removeIV(buffer, size, ivSize)
	return verify(c.mac, buffer, size)
}

func (c *BlockCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
	if c.random != nil {
		c.random.Close()
	}
}

func (c *BlockCipher) SealedRecordOffset() int {
	return PayloadOffset - HeaderSize - c.cipher.BlockSize()
}

// AEADCipher implements TLS 1.2 aead cipher.
type AEADCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *AEADCipher) Open(buffer []byte, size int) ([]byte, error) {
	return nil, nil
}

func (c *AEADCipher) Seal(buffer []byte, size int) ([]byte, error) {
	return nil, nil
}

func (c *AEADCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
}

func (c *AEADCipher) SealedRecordOffset() int { return PayloadOffset - HeaderSize }

func encrypt(cipher okapi.Cipher, buffer []byte, size int, ivSize int) ([]byte, error) {
	if cipher == nil {
		// Return a slice framing the unencrypted record including the header.
		return buffer[PayloadOffset-HeaderSize:][:HeaderSize+size], nil
	}
	// Encrypt everything after the header.
	var fragment = buffer[PayloadOffset-ivSize:][:size]
	ins, outs := cipher.Update(fragment, fragment)
	_assert(ins == size, "cipher input size %d, expected %d", ins, size)
	_assert(outs == size, "cipher output size %d, expected %d", outs, size)
	// Return a slice framing the encrypted record including the header.
	// non-zero ivSize indicates that an explicit IV was inserted between the record header
	// and the fragment thus moving the beginning of the record to the left.
	// Note however that size includes ivSize.
	return buffer[PayloadOffset-HeaderSize-ivSize:][:HeaderSize+size], nil
}

func decrypt(cipher okapi.Cipher, buffer []byte, size int, ivSize int) {
	if cipher == nil {
		return
	}
	// Decrypt everything after the header.
	ciphertext := buffer[PayloadOffset-ivSize:]
	ins, outs := cipher.Update(ciphertext[:size], ciphertext)
	_assert(ins == size, "cipher input size %d, expected %d", ins, size)
	_assert(outs == size, "cipher output size %d, expected %d", outs, size)
}

func addPadding(cipher okapi.Cipher, buffer []byte, size int, ivSize int, random Random) int {
	// TODO: Add randomized padding length
	var pad = byte(cipher.BlockSize())
	pad = pad - byte((size+1)%int(pad))
	padField := buffer[PayloadOffset-ivSize+size:]
	for i := byte(0); i <= pad; i++ {
		padField[i] = pad
	}
	size += int(pad) + 1
	// Update the length field in the record header to include the padding
	var lengthField = buffer[PayloadOffset-HeaderSize-ivSize+3:][:2]
	binary.BigEndian.PutUint16(lengthField, uint16(size))
	return size
}

func removePadding(cipher okapi.Cipher, buffer []byte, size int, ivSize int) int {
	var pad = int(buffer[PayloadOffset-ivSize+size-1])
	size -= 1 + int(pad)
	// Update the length field in the record header to exclude the padding
	var lengthField = buffer[PayloadOffset-HeaderSize-ivSize+3:][:2]
	binary.BigEndian.PutUint16(lengthField, uint16(size))
	return size
}

func insertIV(buffer []byte, size int, ivSize int, random Random) int {
	if random == nil {
		random = DefaultRandom // Use default Random.
	}
	// Shift record header left to make room for the IV.
	// We're overwriting the seq_num but we don't need it anymore.
	var record = buffer[PayloadOffset-HeaderSize-ivSize:]
	copy(record, record[ivSize:][:HeaderSize])
	// Generate the IV into the gap between the header and the body.
	_, err := random.Read(record[HeaderSize:][:ivSize])
	_assert(err == nil, "IV generation failed %s", err)
	size += ivSize
	// Update the length field in the record header to include the explict IV
	binary.BigEndian.PutUint16(record[3:5], uint16(size))
	return size
}

func removeIV(buffer []byte, size int, ivSize int) int {
	// Shift record header+seq_num right over the IV.
	var record = buffer[PayloadOffset-HeaderSize-ivSize-8:]
	copy(record[ivSize:], record[:HeaderSize+8])
	size -= ivSize
	var lengthField = buffer[PayloadOffset-HeaderSize+3:][:2]
	binary.BigEndian.PutUint16(lengthField, uint16(size))
	return size
}

func sign(mac okapi.Hash, buffer []byte, size int) int {
	// Update the length field in the header with the data size.
	lengthHeader := buffer[PayloadOffset-HeaderSize+3:][:2]
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	if mac == nil {
		return size
	}
	// Hash whole buffer (including the seq_num and record header),
	// but excluding the explicit IV room at the beginning.
	mac.Write(buffer[PayloadOffset-HeaderSize-8 : PayloadOffset+size])
	// Append the digest at the end.
	size += copy(buffer[PayloadOffset+size:], mac.Digest())
	mac.Reset()
	// Update the length field in the header to include the digest
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	return size
}

func verify(mac okapi.Hash, buffer []byte, size int) ([]byte, error) {
	//fmt.Printf("Signed: %q\n", buffer[:HeaderSize+8+size])
	if mac == nil {
		return buffer[PayloadOffset:][:size], nil
	}
	size -= mac.Size()
	// Adjust the length field in the header to exclude the record digest,
	// so that we can feed the buffer directly into to the MAC function.
	lengthHeader := buffer[PayloadOffset-HeaderSize+3:][:2]
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	// Hash whole buffer (including the seq_num and record header),
	mac.Write(buffer[PayloadOffset-HeaderSize-8:][:8+HeaderSize+size])
	buffer = buffer[PayloadOffset:]
	// Check that the computed digest matches the received digest.
	ok := subtle.ConstantTimeCompare(buffer[size:][:mac.Size()], mac.Digest()) == 1
	mac.Reset()
	if !ok {
		return nil, InvalidRecordMAC
	}
	// Return a slice framing the record payload.
	return buffer[:size], nil
}
