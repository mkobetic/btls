package records

import (
	"bytes"
	"testing"

	"github.com/mkobetic/okapi"
)

var digestSize = map[okapi.HashSpec]int{
	nil:          0,
	okapi.MD5:    16,
	okapi.SHA1:   20,
	okapi.SHA256: 32,
}

func TestCipher_NULL_NULL(t *testing.T)          { testCipher(t, NULL_NULL, TLS10) }
func TestCipher_NULL_MD5(t *testing.T)           { testCipher(t, NULL_MD5, TLS11) }
func TestCipher_NULL_SHA256(t *testing.T)        { testCipher(t, NULL_SHA256, TLS12) }
func TestCipher_NULL_SHA(t *testing.T)           { testCipher(t, NULL_SHA, SSL30) }
func TestCipher_RC4_128_SHA(t *testing.T)        { testCipher(t, RC4_128_SHA, SSL30) }
func TestCipher_RC4_128_MD5(t *testing.T)        { testCipher(t, RC4_128_MD5, TLS10) }
func TestCipher_3DES_EDE_CBC_SHA(t *testing.T)   { testCipher(t, DES_EDE_CBC_SHA, SSL30) }
func TestCipher_AES_128_CBC_SHA(t *testing.T)    { testCipher(t, AES_128_CBC_SHA, TLS10) }
func TestCipher_AES_256_CBC_SHA256(t *testing.T) { testCipher(t, AES_256_CBC_SHA256, TLS12) }
func testCipher(t *testing.T, cs *OkapiCipherSpec, v ProtocolVersion) {
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
	suite := cs.New(v, key, iv, macKey, true, nil)
	defer suite.Close()
	msg := []byte("Hello World!")
	buffer := make([]byte, BufferHeaderSize+len(msg)+MinBufferTrailerSize)
	payload := buffer[BufferHeaderSize:][:len(msg)]
	copy(payload, msg)
	sealed, err := suite.Seal(buffer, len(msg))
	if err != nil {
		t.Fatalf("Seal error: %s", err)
	}
	if !((cs.kind == stream && len(sealed) == HeaderSize+len(msg)+digestSize[cs.MAC]) ||
		(cs.kind == block && len(sealed) > HeaderSize+len(msg)+digestSize[cs.MAC])) {
		t.Fatalf("Wrong Seal output size: %d", len(sealed))
	}
	if cs.Cipher != nil && bytes.Equal(payload, msg) {
		t.Fatalf("Payload not encrypted %s", payload)
	}
	suite = cs.New(v, key, iv, macKey, false, nil)
	defer suite.Close()
	unsealed, err := suite.Open(buffer, len(sealed)-HeaderSize)
	if err != nil {
		t.Fatalf("Open error: %s", err)
	}
	if len(unsealed) != len(msg) {
		t.Fatalf("Wrong Open output size: %d", len(unsealed))
	}
	if !bytes.Equal(payload, msg) {
		t.Fatalf("%s", payload)
	}
}

func Test_ExplicitIV(t *testing.T) {
	buffer := make([]byte, BufferHeaderSize+50)
	for i := 0; i < len(buffer); i++ {
		buffer[i] = byte(i)
	}
	ivSize := 10
	length := insertIV(buffer, 20, ivSize, &FakeRandom{})
	if length != 30 {
		t.Fatalf("Wrong length after insertion: %d", length)
	}
	i := 0
	// Check the unmodified prefix
	for ; i < BufferHeaderSize-HeaderSize-ivSize; i++ {
		if buffer[i] != byte(i) {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
	t.Logf("Prefix ends at %d", i)
	// Check the shifted header
	for ; i < BufferHeaderSize-ivSize-2; i++ {
		if buffer[i] != byte(i+ivSize) {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
	// Check the length field
	if buffer[i] != 0 {
		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	}
	i++
	if buffer[i] != byte(length) {
		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	}
	i++
	// Check the inserted IV
	for ; i < BufferHeaderSize; i++ {
		if buffer[i] != 255 {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
	// Check the record contents
	for ; i < len(buffer); i++ {
		if buffer[i] != byte(i) {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
	//length := removeIV(buffer, length, ivSize)
	//if length != 20 {
	//	t.Fatalf("Wrong length after removal: %d", length)
	//}
	//i = 0
	//// Check the unmodified prefix
	//for ; i < BufferHeaderSize-HeaderSize-ivSize; i++ {
	//	if buffer[i] != byte(i) {
	//		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//	}
	//}
	//// Check the shifted sequence number
	//for ; i < BufferHeaderSize-HeaderSize-ivSize+8; i++ {
	//	if buffer[i] != byte(i-8) {
	//		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//	}
	//}
	//// Check the shifted header
	//for ; i < BufferHeaderSize-ivSize-2; i++ {
	//	if buffer[i] != byte(i+ivSize) {
	//		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//	}
	//}
	//// Check the length field
	//if buffer[i] != 0 {
	//	t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//}
	//i++
	//if buffer[i] != byte(length) {
	//	t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//}
	//i++
	//// Check the inserted IV
	//for ; i < BufferHeaderSize; i++ {
	//	if buffer[i] != 255 {
	//		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//	}
	//}
	//// Check the record contents
	//for ; i < len(buffer); i++ {
	//	if buffer[i] != byte(i) {
	//		t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
	//	}
	//}
}

type FakeRandom struct{}

func (f *FakeRandom) Read(s []byte) (int, error) {
	for i := 0; i < len(s); i++ {
		s[i] = 255
	}
	return len(s), nil
}
func (f *FakeRandom) Close() {}
