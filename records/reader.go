package records

import (
	"errors"
	"io"
)

var (
	UnexpectedRecordContentType = errors.New("Received a record with unexpected content type.")
	WrongRecordVersion          = errors.New("Received a record with wrong protocol version.")
	RecordTooLarge              = errors.New("Incoming record reports length exceeding maximum allowed record size.")
)

// readCloser adapts plain io.Reader to io.ReadCloser
type readCloser struct {
	io.Reader
}

func (r *readCloser) Close() error { return nil }

// Reader extracts payload from properly formed TLS records.
type Reader struct {
	reader      io.ReadCloser   // source of TLS records
	buffer      []byte          // holds the entire TLS record (including the header)
	unread      []byte          // frames the unread part of the payload
	Version     ProtocolVersion // expected record version
	ContentType ContentType     // expected record content type
}

// NewReader creates a Reader that decodes content framed in TLS records.
// The buffer argument enables external buffer management to minimize large allocations.
// It must be large enough to accommodate maximum record size (maxCiphertextLength+headerSize),
// otherwise the Reader will not be created. If buffer is nil a new buffer is allocated.
func NewReader(reader io.ReadCloser, buffer []byte) *Reader {
	if buffer == nil {
		buffer = make([]byte, maxCiphertextLength+headerSize)
	} else if len(buffer) > maxCiphertextLength+headerSize {
		// Make sure buffer does not exceed maximum record length
		buffer = buffer[:maxCiphertextLength+headerSize]
	} else if len(buffer) < maxCiphertextLength+headerSize {
		// buffer must be large enough to fit a largest legal size records
		return nil
	}
	return &Reader{reader: reader, buffer: buffer, ContentType: handshake}
}

// NewReaderIO allows creating a Reader from plain io.Reader
func NewReaderIO(reader io.Reader, buffer []byte) *Reader {
	return NewReader(&readCloser{reader}, buffer)
}

// Read fills p with payload of the expected content type.
func (r *Reader) Read(p []byte) (n int, err error) {
	n = copy(p, r.unread)
	r.unread = r.unread[n:]
	p = p[n:]
	for len(p) > 0 {
		err = r.readRecord()
		if err != nil {
			return n, err
		}
		m := copy(p, r.unread)
		r.unread = r.unread[m:]
		p = p[m:]
		n += m
	}
	return n, nil
}

func (r *Reader) readRecord() error {
	m, err := r.reader.Read(r.buffer[:headerSize])
	if err != nil {
		return err
	}
	l := int(r.buffer[3])<<8 + int(r.buffer[4])
	if l > maxCiphertextLength {
		return RecordTooLarge
	}
	m, err = r.reader.Read(r.buffer[headerSize : headerSize+l])
	if err != nil {
		return err
	}
	r.unread = r.buffer[headerSize : headerSize+m]
	if r.Version != TLSXX && r.recordVersion() != r.Version {
		return WrongRecordVersion
	}
	if r.recordContentType() != r.ContentType {
		return UnexpectedRecordContentType
	}
	return nil
}

func (r *Reader) Close() error {
	return r.reader.Close()
}

// Version returns current protocol version.
func (r *Reader) recordVersion() ProtocolVersion {
	return ProtocolVersion(r.buffer[1])<<8 | ProtocolVersion(r.buffer[2])
}

// ContentType returns current record content type.
func (r *Reader) recordContentType() ContentType {
	return ContentType(r.buffer[0])
}
