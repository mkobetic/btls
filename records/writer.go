package records

import (
	"io"
)

type flusher interface {
	Flush() error
}

// Writer transforms written content into properly formed TLS records.
// Records are flushed automatically when the content fills the configured buffer,
// or explicitly using the Flush method.
type Writer struct {
	writer  io.Writer // destination of written TLS records
	buffer  []byte    // holds the entire TLS record (including the header)
	content []byte    // frames the section of the buffer available for content
	free    []byte    // frames the section of content that is still free
	cipher  Cipher    // seals outgoing records
}

// NewWriter creates a Writer that frames written content using TLS record format.
// The buffer argument enables external buffer management, to minimize large allocations.
// It also controls the maximum size of TLS records that the writer produces.
// If buffer is nil a new buffer is allocated with default (maximum) record size.
func NewWriter(writer io.Writer, buffer []byte) *Writer {
	if buffer == nil {
		buffer = make([]byte, MaxCiphertextLength+HeaderSize)
	} else if len(buffer) > MaxCiphertextLength+HeaderSize {
		// Make sure buffer does not exceed maximum record length
		buffer = buffer[:MaxCiphertextLength+HeaderSize]
	}
	w := &Writer{writer: writer, buffer: buffer}
	content := buffer[HeaderSize : HeaderSize+w.maxPlaintextLength()]
	w.content = content
	w.free = content
	w.SetVersion(SSL30)
	w.SetContentType(Handshake)
	return w
}

// Write buffers b in the writer. If there is not enough room,
// records with older content will be flushed automatically
// into the underlying writer as necessary.
func (w *Writer) Write(b []byte) (int, error) {
	var err error
	flushed := 0
	copied := copy(w.free, b)
	b = b[copied:]
	w.free = w.free[copied:]
	for len(b) > 0 {
		err = w.Flush()
		if err != nil {
			break
		}
		flushed += copied
		copied = copy(w.free, b)
		b = b[copied:]
		w.free = w.free[copied:]
	}
	return flushed + copied, err
}

// Flush emits a record with entire buffered content into the underlying writer.
func (w *Writer) Flush() error {
	length := len(w.content) - len(w.free)
	w.buffer[3] = byte(length >> 8)
	w.buffer[4] = byte(length & 0xFF)
	if _, err := w.writer.Write(w.buffer[:length+HeaderSize]); err != nil {
		return err
	}
	if f, ok := w.writer.(flusher); ok {
		if err := f.Flush(); err != nil {
			return err
		}
	}
	w.free = w.content
	return nil
}

// Close flushes remaining buffered content and releases any associated resources.
func (w *Writer) Close() error {
	if !w.bufferEmpty() {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	if c, ok := w.writer.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Version returns current protocol version.
func (w *Writer) Version() ProtocolVersion {
	return ProtocolVersion(w.buffer[1])<<8 | ProtocolVersion(w.buffer[2])
}

// SetVersion sets current protocol version.
// If previous version is different any buffered content is flushed
// in a record of that version.
func (w *Writer) SetVersion(v ProtocolVersion) error {
	if w.Version() == v {
		return nil
	}
	if !w.bufferEmpty() {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	w.buffer[1] = byte(v >> 8)
	w.buffer[2] = byte(v & 0xFF)
	return nil
}

// ContentType returns current record content type.
func (w *Writer) ContentType() ContentType {
	return ContentType(w.buffer[0])
}

// SetContentType sets current record content type.
// If previous type is different any buffered content is flushed
// in a record of that type.
func (w *Writer) SetContentType(t ContentType) error {
	if w.ContentType() == t {
		return nil
	}
	if !w.bufferEmpty() {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	w.buffer[0] = byte(t)
	return nil
}

func (w *Writer) bufferEmpty() bool {
	return len(w.free) == len(w.content)
}

func (w *Writer) maxPlaintextLength() int {
	//TODO: leave room for padding and MAC (depends on current cipher)
	max := len(w.buffer) - HeaderSize
	if max < MaxPlaintextLength {
		return max
	}
	return MaxPlaintextLength
}
