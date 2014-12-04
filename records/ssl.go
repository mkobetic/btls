package records

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/mkobetic/okapi"
)

// SSL3.0 uses custom MAC.
type SSL30StreamCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *SSL30StreamCipher) Seal(buffer []byte, size int) ([]byte, error) {
	size = signSSL30(c.mac, buffer, size)
	return encrypt(c.cipher, buffer, size, 0)
}

func (c *SSL30StreamCipher) Open(buffer []byte, size int) ([]byte, error) {
	decrypt(c.cipher, buffer, size, 0)
	return verifySSL30(c.mac, buffer, size)
}

func (c *SSL30StreamCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
}

func (c *SSL30StreamCipher) RecordOffset() int {
	return BufferHeaderSize - HeaderSize
}

// SSL3.0 uses custom MAC and implicit IVs.
type SSL30BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *SSL30BlockCipher) Seal(buffer []byte, size int) ([]byte, error) {
	size = signSSL30(c.mac, buffer, size)
	size = addPaddingSSL30(c.cipher, buffer, size)
	return encrypt(c.cipher, buffer, size, 0)
}

func (c *SSL30BlockCipher) Open(buffer []byte, size int) ([]byte, error) {
	decrypt(c.cipher, buffer, size, 0)
	size = removePadding(c.cipher, buffer, size, 0)
	return verifySSL30(c.mac, buffer, size)
}

func (c *SSL30BlockCipher) Close() {
	if c.cipher != nil {
		c.cipher.Close()
	}
	if c.mac != nil {
		c.mac.Close()
	}
}

func (c *SSL30BlockCipher) RecordOffset() int {
	return BufferHeaderSize - HeaderSize
}

func addPaddingSSL30(cipher okapi.Cipher, buffer []byte, size int) int {
	var pad = byte(cipher.BlockSize())
	pad = pad - byte((size+1)%int(pad))
	padField := buffer[BufferHeaderSize+size:]
	for i := byte(0); i <= pad; i++ {
		padField[i] = pad
	}
	size += int(pad) + 1
	// Update the length field in the record header to include the padding
	var lengthField = buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
	binary.BigEndian.PutUint16(lengthField, uint16(size))
	return size
}

func signSSL30(mac okapi.Hash, buffer []byte, size int) int {
	buffer = buffer[BufferHeaderSize-HeaderSize-8:]
	// Update the length field in the header with the data size.
	lengthHeader := buffer[8+3:][:2]
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	if mac == nil {
		return size
	}
	// shift seq_num + type 2 bytes right over version
	var header = buffer[:8+3]
	copy(header[2:], header)
	//mac.Write(buffer[MaxBlockSize : BufferHeaderSize-4])          // seq_num + type +
	//mac.Write(buffer[BufferHeaderSize-2 : BufferHeaderSize+size]) // length + fragment
	mac.Write(buffer[2 : 8+HeaderSize+size])
	// unshift seq_num + type and restore version
	copy(header, header[2:])
	binary.BigEndian.PutUint16(header[8+1:], uint16(SSL30))
	// copy record digest to the end of the record
	size += copy(buffer[8+HeaderSize+size:], mac.Digest())
	mac.Reset()
	// Update the length field in the header to include the digest
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	return size
}

func verifySSL30(mac okapi.Hash, buffer []byte, size int) ([]byte, error) {
	if mac == nil {
		return buffer[BufferHeaderSize:][:size], nil
	}
	size -= mac.Size()
	// Adjust the length field in the header to exclude the record digest,
	// so that we can feed the buffer directly into to the MAC function.
	lengthHeader := buffer[BufferHeaderSize-HeaderSize+3:][:2]
	binary.BigEndian.PutUint16(lengthHeader, uint16(size))
	// shift seq_num + type 2 bytes right over version
	buffer = buffer[BufferHeaderSize-HeaderSize-8:]
	var header = buffer[:8+3]
	copy(header[2:], header)
	//mac.Write(buffer[MaxBlockSize : BufferHeaderSize-4])          // seq_num + type +
	//mac.Write(buffer[BufferHeaderSize-2 : BufferHeaderSize+size]) // length + fragment
	mac.Write(buffer[2 : 8+HeaderSize+size])
	// unshift seq_num + type and restore version
	copy(header, header[2:])
	binary.BigEndian.PutUint16(header[8+1:], uint16(SSL30))
	buffer = buffer[8+HeaderSize:]
	ok := subtle.ConstantTimeCompare(buffer[size:][:mac.Size()], mac.Digest()) == 1
	mac.Reset()
	if !ok {
		return nil, InvalidRecordMAC
	}
	return buffer[:size], nil
}
