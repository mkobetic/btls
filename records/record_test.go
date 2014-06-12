package records

import (
	"bytes"
	"testing"
)

func Test_RW_NULL_NULL(t *testing.T) { testReadWrite(t, 16384, 1024, NULL_NULL, TLS10) }
func Test_RW_NULL_MD5(t *testing.T)  { testReadWrite(t, 16384, 1024, NULL_MD5, TLS11) }
func Test_RW_NULL_SHA(t *testing.T)  { testReadWrite(t, 16384, 1024, NULL_SHA, SSL30) }

func Test_RW_RC4_128_MD5(t *testing.T) { testReadWrite(t, 16384, 1024, RC4_128_MD5, SSL30) }
func Test_RW_RC4_128_SHA(t *testing.T) { testReadWrite(t, 16384, 1024, RC4_128_SHA, TLS12) }

func Test_RW_3DES_EDE_CBC_SHA(t *testing.T) { testReadWrite(t, 16384, 1024, DES_EDE_CBC_SHA, SSL30) }
func Test_RW_AES_128_CBC_SHA(t *testing.T)  { testReadWrite(t, 16384, 1024, AES_128_CBC_SHA, TLS10) }
func Test_RW_AES_256_CBC_SHA256(t *testing.T) {
	testReadWrite(t, 16384, 1024, AES_256_CBC_SHA256, TLS12)
}
func testReadWrite(t *testing.T, payloadSize int, recordSize int, cs *CipherSpec, v ProtocolVersion) {
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
	buffer := new(bytes.Buffer)
	w := NewWriter(buffer, make([]byte, recordSize+MinBufferTrailerSize))
	w.SetCipher(cs, v, key, iv, macKey, nil)
	r := NewReader(buffer, nil)
	r.SetCipher(cs, v, key, iv, macKey)
	payload := make([]byte, payloadSize)
	var size int
	var err error
	if size, err = w.Write(payload); size != payloadSize || err != nil {
		t.Fatalf("Write size=%d err=%s\n", size, err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal("Flush failed: %s", err)
	}
	if size, err = r.Read(payload); err != nil {
		t.Fatalf("Read size=%d err=%s\n", size, err)
	}
	buffer.Reset()
}
