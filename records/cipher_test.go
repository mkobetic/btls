package records

import (
	"bytes"
	"testing"
)

var digestSize = map[CipherSpec]int{
	NULL_NULL:   0,
	NULL_MD5:    16,
	NULL_SHA:    20,
	NULL_SHA256: 32,
}

func TestCipher_NULL_NULL(t *testing.T)   { testCipher(t, NULL_NULL, TLS10) }
func TestCipher_NULL_MD5(t *testing.T)    { testCipher(t, NULL_MD5, TLS11) }
func TestCipher_NULL_SHA256(t *testing.T) { testCipher(t, NULL_SHA256, TLS12) }
func TestCipher_NULL_SHA(t *testing.T)    { testCipher(t, NULL_SHA, SSL30) }
func testCipher(t *testing.T, cs CipherSpec, v ProtocolVersion) {
	var key, iv, macKey []byte
	if cs.CipherKeySize > 0 {
		key = bytes.Repeat([]byte{42}, cs.CipherKeySize)
	}
	if cs.kind == block {
		var blockSize int
		if cs == DES_EDE_CBC_SHA {
			blockSize = 8
		} else {
			blockSize = 16
		}
		iv = bytes.Repeat([]byte{42}, blockSize)
	}
	if cs.MACKeySize > 0 {
		macKey = bytes.Repeat([]byte{42}, cs.MACKeySize)
	}
	suite := NewCipher(cs, v, key, iv, macKey, true)
	defer suite.Close()
	msg := []byte("Hello World!")
	buffer := make([]byte, BufferHeaderSize+len(msg)+32)
	payload := buffer[BufferHeaderSize:][:len(msg)]
	copy(payload, msg)
	size, err := suite.Seal(buffer, len(msg))
	if err != nil {
		t.Fatalf("Seal error: %s", err)
	}
	if size != len(msg)+digestSize[cs] {
		t.Fatalf("Wrong Seal output size: %d", size)
	}
	suite = NewCipher(cs, v, key, iv, macKey, false)
	defer suite.Close()
	size, err = suite.Open(buffer, size)
	if err != nil {
		t.Fatalf("Open error: %s", err)
	}
	if size != len(msg) {
		t.Fatalf("Wrong Open output size: %d", size)
	}
	if !bytes.Equal(payload, msg) {
		t.Fatalf("%s", payload)
	}
}
