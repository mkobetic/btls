package records

import (
	"bytes"
	"fmt"
	//"io"
	//"os"
	//"syscall"
	"testing"
)

func BenchmarkWrite16K_128(b *testing.B)  { benchmarkWrite(b, 128) }
func BenchmarkWrite16K_256(b *testing.B)  { benchmarkWrite(b, 256) }
func BenchmarkWrite16K_512(b *testing.B)  { benchmarkWrite(b, 512) }
func BenchmarkWrite16K_1024(b *testing.B) { benchmarkWrite(b, 1024) }
func BenchmarkWrite16K_2048(b *testing.B) { benchmarkWrite(b, 2048) }
func BenchmarkWrite16K_4096(b *testing.B) { benchmarkWrite(b, 4096) }
func BenchmarkWrite16K_8192(b *testing.B) { benchmarkWrite(b, 8192) }
func benchmarkWrite(b *testing.B, size int) {
	buffer := new(bytes.Buffer)
	w := NewWriter(buffer, make([]byte, size))
	in := make([]byte, 16384)
	for n := 0; n < b.N; n++ {
		w.Write(in)
		buffer.Reset()
	}
}

func BenchmarkRead16K_128(b *testing.B)  { benchmarkRead(b, 128) }
func BenchmarkRead16K_256(b *testing.B)  { benchmarkRead(b, 256) }
func BenchmarkRead16K_512(b *testing.B)  { benchmarkRead(b, 512) }
func BenchmarkRead16K_1024(b *testing.B) { benchmarkRead(b, 1024) }
func BenchmarkRead16K_2048(b *testing.B) { benchmarkRead(b, 2048) }
func BenchmarkRead16K_4096(b *testing.B) { benchmarkRead(b, 4096) }
func benchmarkRead(b *testing.B, size int) {
	buffer := new(bytes.Buffer)
	content := make([]byte, 16384)
	w := NewWriter(buffer, make([]byte, size))
	w.Write(content)
	records := buffer.Bytes()
	for n := 0; n < b.N; n++ {
		buffer := bytes.NewBuffer(records)
		r := NewReader(buffer, nil)
		r.Read(content)
	}
}

func Benchmark16K_NULL_SHA_TLS10(b *testing.B)    { benchmarkRW(b, 4096, 16384, NULL_SHA, TLS10) }
func Benchmark16K_RC4_128_SHA_TLS10(b *testing.B) { benchmarkRW(b, 4096, 16384, RC4_128_SHA, TLS10) }
func benchmarkRW(b *testing.B, payloadSize int, recordSize int, cs *CipherSpec, v ProtocolVersion) {
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
	for n := 0; n < b.N; n++ {
		if size, err := w.Write(payload); size != payloadSize || err != nil {
			panic(fmt.Sprintf("Write size=%d err=%s", size, err))
		}
		if size, err := r.Read(payload); err != nil {
			panic(fmt.Sprintf("Read size=%d err=%s", size, err))
		}
		buffer.Reset()
	}
}

//func BenchmarkReadWritePipe16K_128(b *testing.B)  { benchmarkReadWritePipe(b, 128) }
//func BenchmarkReadWritePipe16K_256(b *testing.B)  { benchmarkReadWritePipe(b, 256) }
//func BenchmarkReadWritePipe16K_512(b *testing.B)  { benchmarkReadWritePipe(b, 512) }
//func BenchmarkReadWritePipe16K_1024(b *testing.B) { benchmarkReadWritePipe(b, 1024) }
//func BenchmarkReadWritePipe16K_2048(b *testing.B) { benchmarkReadWritePipe(b, 2048) }
//func BenchmarkReadWritePipe16K_4096(b *testing.B) { benchmarkReadWritePipe(b, 4096) }
//func benchmarkReadWritePipe(b *testing.B, size int) {
//	pin, pout := io.Pipe()
//	defer func() { pout.Close(); pin.Close() }()
//	w := NewWriter(pout, make([]byte, size))
//	r := NewReader(pin, nil)
//	in := make([]byte, 4096)
//	out := make([]byte, 4096)
//	for n := 0; n < b.N; n++ {
//		w.Write(in)
//		r.Read(out)
//	}
//}

//func BenchmarkReadWriteSocket16K_128(b *testing.B)  { benchmarkReadWriteSocket(b, 128) }
//func BenchmarkReadWriteSocket16K_256(b *testing.B)  { benchmarkReadWriteSocket(b, 256) }
//func BenchmarkReadWriteSocket16K_512(b *testing.B)  { benchmarkReadWriteSocket(b, 512) }
//func BenchmarkReadWriteSocket16K_1024(b *testing.B) { benchmarkReadWriteSocket(b, 1024) }
//func BenchmarkReadWriteSocket16K_2048(b *testing.B) { benchmarkReadWriteSocket(b, 2048) }
//func BenchmarkReadWriteSocket16K_4096(b *testing.B) { benchmarkReadWriteSocket(b, 4096) }
//func benchmarkReadWriteSocket(b *testing.B, size int) {
//	pin, pout, err := socketpair()
//	if err != nil {
//		panic(err)
//	}
//	defer func() { pout.Close(); pin.Close() }()
//	w := NewWriter(pout, make([]byte, size))
//	r := NewReader(pin, nil)
//	in := make([]byte, 4096)
//	out := make([]byte, 4096)
//	for n := 0; n < b.N; n++ {
//		w.Write(in)
//		r.Read(out)
//	}
//}

//func socketpair() (a, b *os.File, err error) {
//	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
//	if err != nil {
//		return nil, nil, err
//	}
//	a = os.NewFile(uintptr(fds[0]), "a")
//	b = os.NewFile(uintptr(fds[1]), "b")
//	return a, b, nil
//}
