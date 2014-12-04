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

func TestCipher_NULL_NULL_TLS10(t *testing.T)          { testCipher(t, NULL_NULL, TLS10) }
func TestCipher_NULL_MD5_TLS11(t *testing.T)           { testCipher(t, NULL_MD5, TLS11) }
func TestCipher_NULL_SHA256_TLS12(t *testing.T)        { testCipher(t, NULL_SHA256, TLS12) }
func TestCipher_NULL_SHA_SSL30(t *testing.T)           { testCipher(t, NULL_SHA, SSL30) }
func TestCipher_RC4_128_SHA_SSL30(t *testing.T)        { testCipher(t, RC4_128_SHA, SSL30) }
func TestCipher_RC4_128_MD5_TLS10(t *testing.T)        { testCipher(t, RC4_128_MD5, TLS10) }
func TestCipher_3DES_EDE_CBC_SHA_SSL30(t *testing.T)   { testCipher(t, DES_EDE_CBC_SHA, SSL30) }
func TestCipher_AES_128_CBC_SHA_TLS10(t *testing.T)    { testCipher(t, AES_128_CBC_SHA, TLS10) }
func TestCipher_3DES_EDE_CBC_SHA_TLS11(t *testing.T)   { testCipher(t, DES_EDE_CBC_SHA, TLS11) }
func TestCipher_AES_256_CBC_SHA256_TLS12(t *testing.T) { testCipher(t, AES_256_CBC_SHA256, TLS12) }
func testCipher(t *testing.T, cs *OkapiCipherSpec, v ProtocolVersion) {
	var key, iv, macKey []byte
	if cs.Cipher != nil {
		key = bytes.Repeat([]byte{42}, cs.CipherKeySize)
		if cs.kind == block && v < TLS11 {
			iv = bytes.Repeat([]byte{42}, cs.CipherBlockSize)
		}
	}
	if cs.MAC != nil {
		macKey = bytes.Repeat([]byte{42}, cs.MACKeySize)
	}
	suite := cs.New(v, key, iv, macKey, true, &FakeRandom{})
	defer suite.Close()
	msg := []byte("Hello World!")
	buffer := make([]byte, PayloadOffset+len(msg)+MinBufferTrailerSize)
	payload := buffer[PayloadOffset:][:len(msg)]
	copy(payload, msg)
	sealed, err := suite.Seal(buffer, len(msg))
	if err != nil {
		t.Fatalf("Seal error: %s", err)
	}
	var expected int
	if cs.kind == stream {
		expected = HeaderSize + len(msg) + digestSize[cs.MAC]
	} else {
		expected = len(msg) + digestSize[cs.MAC]
		if v > TLS10 {
			expected += cs.CipherBlockSize
		}
		expected = (expected/cs.CipherBlockSize+1)*cs.CipherBlockSize + HeaderSize
	}
	if len(sealed) != expected {
		t.Fatalf("Wrong Seal output size %d, expected %d", len(sealed), expected)
	}
	if cs.Cipher != nil && bytes.Equal(payload, msg) {
		t.Fatalf("Payload not encrypted %s", payload)
	}
	suite = cs.New(v, key, iv, macKey, false, &FakeRandom{})
	defer suite.Close()
	buffer = make([]byte, len(buffer))
	copy(buffer[suite.SealedRecordOffset():], sealed)
	if !bytes.Equal(sealed, buffer[suite.SealedRecordOffset():][:len(sealed)]) {
		t.Fatal("WTF!")
	}
	unsealed, err := suite.Open(buffer, len(sealed)-HeaderSize)
	if err != nil {
		t.Fatalf("Open error: %s", err)
	}
	if len(unsealed) != len(msg) {
		t.Fatalf("Wrong Open output size: %d", len(unsealed))
	}
	if !bytes.Equal(unsealed, msg) {
		t.Fatalf("%s", payload)
	}
}

func Test_InsertIV(t *testing.T) {
	buffer := make([]byte, PayloadOffset+50)
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
	for ; i < PayloadOffset-HeaderSize-ivSize; i++ {
		if buffer[i] != byte(i) {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
	// Check the shifted header
	for ; i < PayloadOffset-ivSize-2; i++ {
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
	for ; i < PayloadOffset; i++ {
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
}

func Test_RemoveIV(t *testing.T) {
	buffer := make([]byte, PayloadOffset+50)
	for i := 0; i < len(buffer); i++ {
		buffer[i] = byte(i)
	}
	ivSize := 10
	length := removeIV(buffer, 30, ivSize)
	if length != 20 {
		t.Fatalf("Wrong length after removal: %d", length)
	}
	i := 0
	// Check the unmodified prefix
	for ; i < PayloadOffset-HeaderSize-8; i++ {
		if buffer[i] != byte(i) {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
	// Check the shifted sequence number and header
	for ; i < PayloadOffset-HeaderSize+3; i++ {
		if buffer[i] != byte(i-ivSize) {
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
	// Check the record contents
	for ; i < len(buffer); i++ {
		if buffer[i] != byte(i) {
			t.Fatalf("Wrong value at index %d: %d", i, buffer[i])
		}
	}
}

type FakeRandom struct{}

func (f *FakeRandom) Read(s []byte) (int, error) {
	for i := 0; i < len(s); i++ {
		s[i] = 255
	}
	return len(s), nil
}
func (f *FakeRandom) Close() {}
