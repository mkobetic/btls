package records

import (
	"errors"
	"fmt"
)

type ProtocolVersion uint16

const (
	TLSXX ProtocolVersion = 0x0000 // unspecified protocol version
	SSL30 ProtocolVersion = 0x0300
	TLS10 ProtocolVersion = 0x0301
	TLS11 ProtocolVersion = 0x0302
	TLS12 ProtocolVersion = 0x0303
)

type ContentType uint8

const (
	ChangeCipherSpec ContentType = 20
	Alert            ContentType = 21
	Handshake        ContentType = 22
	ApplicationData  ContentType = 23
)

const (
	HeaderSize          = 5
	MaxPlaintextLength  = 1 << 14
	MaxCompressedLength = MaxPlaintextLength + 1024
	MaxCiphertextLength = MaxCompressedLength + 1024
)

const (
	// Buffer holds seq_num (uint64) before the full TLS record
	BufferHeaderSize = HeaderSize + 8
	// Minimum space required at the end of the buffer to accommodate
	// largest MAC and padding for the largest block cipher (= block size)
	MinBufferTrailerSize = 16 + 32
)

var (
	InvalidRecordMAC             = errors.New("Invalid record MAC!")
	RecordSequenceNumberOverflow = errors.New("Maximum record sequence number reached!")
	UnexpectedRecordContentType  = errors.New("Received a record with unexpected content type.")
	WrongRecordVersion           = errors.New("Received a record with wrong protocol version.")
	RecordTooLarge               = errors.New("Incoming record reports length exceeding maximum allowed record size.")
)

//type Record struct {
//	contentType ContentType
//	version     ProtocolVersion
//	length      uint16
//}

// Helpers

func _assert(v bool, msg string, params ...interface{}) {
	if !v {
		panic(fmt.Sprintf(msg, params...))
	}
}
