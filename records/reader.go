package records

import (
	"encoding/binary"
	"io"
)

// Reader extracts payload from properly formed TLS records.
type Reader struct {
	reader      io.Reader       // source of TLS records
	buffer      []byte          // holds the entire TLS record with seq_num prepended
	record      []byte          // frames the entire TLS record (including the header)
	unread      []byte          // frames the unread part of the payload
	cipher      Cipher          // opens incoming sealed record
	seqNum      uint64          // current record number
	Version     ProtocolVersion // expected record version
	ContentType ContentType     // expected record content type
}

// NewReader creates a Reader that decodes content framed in TLS records.
// The buffer argument enables external buffer management to minimize large allocations.
// It must be large enough to accommodate maximum record size (maxCiphertextLength+headerSize),
// otherwise the Reader will not be created. If buffer is nil a new buffer is allocated.
func NewReader(reader io.Reader, buffer []byte) *Reader {
	if buffer == nil {
		buffer = make([]byte, MaxCiphertextLength+HeaderSize)
	} else if len(buffer) > MaxCiphertextLength+HeaderSize {
		// Make sure buffer does not exceed maximum record length
		buffer = buffer[:MaxCiphertextLength+HeaderSize]
	} else if len(buffer) < MaxCiphertextLength+HeaderSize {
		// buffer must be large enough to fit a largest legal size record
		return nil
	}
	r := &Reader{reader: reader, buffer: buffer, ContentType: Handshake}
	r.record = buffer[BufferHeaderSize-HeaderSize:] // first 8 bytes are seq_num
	r.SetCipher(NULL_NULL, SSL30, nil, nil, nil)
	return r
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
	m, err := r.reader.Read(r.record[:HeaderSize])
	if err != nil {
		return err
	}
	_assert(m == HeaderSize, "incomplete record header read %d", m)
	if r.Version != TLSXX && r.recordVersion() != r.Version {
		return WrongRecordVersion
	}
	if r.recordContentType() != r.ContentType {
		return UnexpectedRecordContentType
	}
	length := int(r.record[3])<<8 + int(r.record[4])
	if length > MaxCiphertextLength {
		return RecordTooLarge
	}
	r.unread = r.record[HeaderSize : HeaderSize+length]
	m, err = r.reader.Read(r.unread)
	if err != nil {
		return err
	}
	_assert(m == length, "incomplete record read %d, expected %d", m, length)

	binary.BigEndian.PutUint64(r.buffer[0:8], r.seqNum)
	r.seqNum += 1
	if r.seqNum == 0xFFFFFFFFFFFFFFFF {
		return RecordSequenceNumberOverflow
	}

	length, err = r.cipher.Open(r.buffer, length)
	if err != nil {
		return err
	}
	r.unread = r.unread[:length]
	return nil
}

func (r *Reader) Close() error {
	if c, ok := r.reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (r *Reader) SetCipher(cs *CipherSpec, v ProtocolVersion, key, iv, macKey []byte) error {
	r.cipher = cs.New(v, key, iv, macKey, false, nil)
	return nil
}

// Version returns current protocol version.
func (r *Reader) recordVersion() ProtocolVersion {
	return ProtocolVersion(r.record[1])<<8 | ProtocolVersion(r.record[2])
}

// ContentType returns current record content type.
func (r *Reader) recordContentType() ContentType {
	return ContentType(r.record[0])
}
