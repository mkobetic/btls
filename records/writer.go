package records

import (
	"encoding/binary"
	"github.com/mkobetic/okapi"
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
	buffer  []byte    // holds the entire TLS record with seq_num prepended
	record  []byte    // frames the entire TLS record (including the header)
	content []byte    // frames the section of the record available for content
	free    []byte    // frames the section of content that is still free
	cipher  Cipher    // seals outgoing records
	seqNum  uint64    // current record number
}

// NewWriter creates a Writer that frames written content using TLS record format.
// The buffer argument enables external buffer management, to minimize large allocations.
// It also controls the maximum size of TLS records that the writer produces.
// If buffer is nil a new buffer is allocated with default (maximum) record size.
func NewWriter(writer io.Writer, buffer []byte) *Writer {
	maxSize := MaxCiphertextLength + BufferHeaderSize
	if buffer == nil {
		buffer = make([]byte, maxSize)
	} else if len(buffer) > maxSize {
		// Make sure buffer does not exceed maximum record length
		buffer = buffer[:maxSize]
	}
	w := &Writer{writer: writer, buffer: buffer}
	w.record = buffer[BufferHeaderSize-HeaderSize:] // first 8 bytes are seq_num
	content := w.record[HeaderSize : HeaderSize+w.maxPlaintextLength()]
	w.content = content
	w.free = content
	w.SetVersion(SSL30)
	w.SetContentType(Handshake)
	w.SetCipher(NULL_NULL, SSL30, nil, nil, nil, nil)
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
func (w *Writer) Flush() (err error) {
	length := len(w.content) - len(w.free)
	binary.BigEndian.PutUint64(w.buffer[0:8], w.seqNum)
	w.seqNum += 1
	if w.seqNum == 0xFFFFFFFFFFFFFFFF {
		return RecordSequenceNumberOverflow
	}
	if length, err = w.cipher.Seal(w.buffer, length); err != nil {
		return err
	}
	if _, err = w.writer.Write(w.record[:length+HeaderSize]); err != nil {
		return err
	}
	if f, ok := w.writer.(flusher); ok {
		if err = f.Flush(); err != nil {
			return err
		}
	}
	w.free = w.content
	return err
}

// Close flushes remaining buffered content and releases any associated resources.
func (w *Writer) Close() error {
	if !w.bufferEmpty() {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	w.cipher.Close()
	if c, ok := w.writer.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Version returns current protocol version.
func (w *Writer) Version() ProtocolVersion {
	return ProtocolVersion(w.record[1])<<8 | ProtocolVersion(w.record[2])
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
	w.record[1] = byte(v >> 8)
	w.record[2] = byte(v & 0xFF)
	return nil
}

// ContentType returns current record content type.
func (w *Writer) ContentType() ContentType {
	return ContentType(w.record[0])
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
	w.record[0] = byte(t)
	return nil
}

// SetCipher reconfigures the Writer with the new security parameters.
// If there is any previously buffered content, it is flushed in a record
// protected with the previous security parameters.
func (w *Writer) SetCipher(cs *CipherSpec, v ProtocolVersion, key, iv, macKey []byte, random okapi.Random) error {
	if !w.bufferEmpty() {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	w.cipher = cs.New(v, key, iv, macKey, true, random)
	return nil
}

func (w *Writer) bufferEmpty() bool {
	return len(w.free) == len(w.content)
}

func (w *Writer) maxPlaintextLength() int {
	// Leave room for padding (max cipher block size) and mac (max digest size)
	max := len(w.record) - HeaderSize - MinBufferTrailerSize
	if max < MaxPlaintextLength {
		return max
	}
	return MaxPlaintextLength
}
