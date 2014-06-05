package records

import (
	"crypto/subtle"
	"encoding/binary"
	"github.com/mkobetic/okapi"
)

// SSL30 uses custom MAC and implicit IVs
type SSL30StreamCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *SSL30StreamCipher) Seal(buffer []byte, size int) (int, error) {
	size = signSSL30(c.mac, buffer, size)
	encrypt(c.cipher, buffer, size)
	return size, nil
}

func (c *SSL30StreamCipher) Open(buffer []byte, size int) (int, error) {
	decrypt(c.cipher, buffer, size)
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

type SSL30BlockCipher struct {
	cipher okapi.Cipher
	mac    okapi.Hash
}

func (c *SSL30BlockCipher) Seal(buffer []byte, size int) (int, error) {
	size = signSSL30(c.mac, buffer, size)
	size = addPaddingSSL30(c.cipher, buffer, size)
	encrypt(c.cipher, buffer, size)
	return size, nil
}

func (c *SSL30BlockCipher) Open(buffer []byte, size int) (int, error) {
	decrypt(c.cipher, buffer, size)
	size = removePadding(c.cipher, buffer, size)
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

func addPaddingSSL30(cipher okapi.Cipher, buffer []byte, size int) int {
	var pad = byte(cipher.BlockSize())
	pad = pad - byte((size+1)%int(pad))
	buffer = buffer[BufferHeaderSize+size:]
	for i := byte(0); i <= pad; i++ {
		buffer[i] = pad
	}
	size = size + int(pad) + 1
	lengthField := buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
	binary.BigEndian.PutUint16(lengthField, uint16(size))
	return size
}

func signSSL30(mac okapi.Hash, buffer []byte, size int) int {
	length := buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
	binary.BigEndian.PutUint16(length, uint16(size))
	if mac == nil {
		return size
	}
	mac.Write(buffer[:BufferHeaderSize-4])                        // seq_num + type +
	mac.Write(buffer[BufferHeaderSize-2 : BufferHeaderSize+size]) // length + fragment
	size += copy(buffer[BufferHeaderSize+size:], mac.Digest())
	mac.Reset()
	binary.BigEndian.PutUint16(length, uint16(size))
	return size
}

func verifySSL30(mac okapi.Hash, buffer []byte, size int) (int, error) {
	if mac == nil {
		return size, nil
	}
	size -= mac.Size()
	length := buffer[BufferHeaderSize-HeaderSize+3 : BufferHeaderSize-HeaderSize+5]
	binary.BigEndian.PutUint16(length, uint16(size))
	mac.Write(buffer[:BufferHeaderSize-4])                        // seq_num + type +
	mac.Write(buffer[BufferHeaderSize-2 : BufferHeaderSize+size]) // length + fragment
	buffer = buffer[BufferHeaderSize+size:]
	ok := subtle.ConstantTimeCompare(buffer[:mac.Size()], mac.Digest()) == 1
	mac.Reset()
	if !ok {
		return size, InvalidRecordMAC
	}
	return size, nil
}
