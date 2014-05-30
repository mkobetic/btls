package records

import (
	"bytes"
	"github.com/mkobetic/okapi"
	"testing"
)

var digestSize = map[okapi.HashSpec]int{
	nil:          0,
	okapi.MD5:    16,
	okapi.SHA1:   20,
	okapi.SHA256: 32,
}

func TestCipher_NULL_NULL(t *testing.T)        { testCipher(t, NULL_NULL, TLS10) }
func TestCipher_NULL_MD5(t *testing.T)         { testCipher(t, NULL_MD5, TLS11) }
func TestCipher_NULL_SHA256(t *testing.T)      { testCipher(t, NULL_SHA256, TLS12) }
func TestCipher_NULL_SHA(t *testing.T)         { testCipher(t, NULL_SHA, SSL30) }
func TestCipher_RC4_128_SHA(t *testing.T)      { testCipher(t, RC4_128_SHA, SSL30) }
func TestCipher_RC4_128_MD5(t *testing.T)      { testCipher(t, RC4_128_MD5, TLS10) }
func TestCipher_3DES_EDE_CBC_SHA(t *testing.T) { testCipher(t, DES_EDE_CBC_SHA, SSL30) }
func TestCipher_AES_128_CBC_SHA(t *testing.T)  { testCipher(t, AES_128_CBC_SHA, TLS10) }
func testCipher(t *testing.T, cs CipherSpec, v ProtocolVersion) {
	var key, iv, macKey []byte
	if cs.Cipher != nil {
		key = bytes.Repeat([]byte{42}, cs.CipherKeySize)
		if cs.kind == block {
			iv = bytes.Repeat([]byte{42}, cs.CipherBlockSize)
		}
	}
	if cs.MAC != nil {
		macKey = bytes.Repeat([]byte{42}, cs.MACKeySize)
	}
	suite := NewCipher(cs, v, key, iv, macKey, true)
	defer suite.Close()
	msg := []byte("Hello World!")
	buffer := make([]byte, BufferHeaderSize+len(msg)+MinBufferTrailerSize)
	payload := buffer[BufferHeaderSize:][:len(msg)]
	copy(payload, msg)
	size, err := suite.Seal(buffer, len(msg))
	if err != nil {
		t.Fatalf("Seal error: %s", err)
	}
	if !((cs.kind == stream && size == len(msg)+digestSize[cs.MAC]) ||
		(cs.kind == block && size > len(msg)+digestSize[cs.MAC])) {
		t.Fatalf("Wrong Seal output size: %d", size)
	}
	if cs.Cipher != nil && bytes.Equal(payload, msg) {
		t.Fatalf("Payload not encrypted %s", payload)
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
