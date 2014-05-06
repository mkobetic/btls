package records

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkReadWrite16K_128(b *testing.B)  { benchmarkReadWrite(b, 128) }
func BenchmarkReadWrite16K_256(b *testing.B)  { benchmarkReadWrite(b, 256) }
func BenchmarkReadWrite16K_512(b *testing.B)  { benchmarkReadWrite(b, 512) }
func BenchmarkReadWrite16K_1024(b *testing.B) { benchmarkReadWrite(b, 1024) }
func BenchmarkReadWrite16K_2048(b *testing.B) { benchmarkReadWrite(b, 2048) }
func BenchmarkReadWrite16K_4096(b *testing.B) { benchmarkReadWrite(b, 4096) }
func benchmarkReadWrite(b *testing.B, size int) {
	buffer := bytes.NewBuffer(make([]byte, 20000))
	w := NewWriterIO(buffer, make([]byte, size))
	r := NewReaderIO(buffer, nil)
	in := make([]byte, 16384)
	out := make([]byte, 16384)
	for n := 0; n < b.N; n++ {
		w.Write(in)
		r.Read(out)
	}
}

func BenchmarkReadWritePipe16K_128(b *testing.B)  { benchmarkReadWritePipe(b, 128) }
func BenchmarkReadWritePipe16K_256(b *testing.B)  { benchmarkReadWritePipe(b, 256) }
func BenchmarkReadWritePipe16K_512(b *testing.B)  { benchmarkReadWritePipe(b, 512) }
func BenchmarkReadWritePipe16K_1024(b *testing.B) { benchmarkReadWritePipe(b, 1024) }
func BenchmarkReadWritePipe16K_2048(b *testing.B) { benchmarkReadWritePipe(b, 2048) }
func BenchmarkReadWritePipe16K_4096(b *testing.B) { benchmarkReadWritePipe(b, 4096) }
func benchmarkReadWritePipe(b *testing.B, size int) {
	pin, pout := io.Pipe()
	defer func() { pout.Close(); pin.Close() }()
	w := NewWriterIO(pout, make([]byte, size))
	r := NewReaderIO(pin, nil)
	in := make([]byte, 16384)
	out := make([]byte, 16384)
	for n := 0; n < b.N; n++ {
		w.Write(in)
		r.Read(out)
	}
}
