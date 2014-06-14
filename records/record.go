/*
Package records implements the record layer of SSL/TLS protocol,
responsible for encryption and integrity of the payload.

Main API is represented by the Reader and Writer that transparently
translate plain payload to/from the prescribed record frames according
to the configured protocol version and security parameters.

Cryptographic protection is provided by Ciphers which are created from
CipherSpecs and appropriate keying material. In this context a Cipher represents
specific combination of an encryption and MAC algorithm. There are several Cipher
implementations reflecting the nuances of different Cipher types and ProtocolVersions.
*/
package records

import (
	"errors"
	"fmt"
)

type ProtocolVersion uint16

const (
	TLSXX ProtocolVersion = 0x0000 // unspecified protocol version
	SSL30 ProtocolVersion = 0x0300 // SSL 3.0
	TLS10 ProtocolVersion = 0x0301 // TLS 1.0
	TLS11 ProtocolVersion = 0x0302 // TLS 1.1
	TLS12 ProtocolVersion = 0x0303 // TLS 1.2
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
	// largest MAC and padding for the largest block cipher and explicit IV (2 x block size)
	MinBufferTrailerSize = 32 + 16 + 16
)

var (
	InvalidRecordMAC             = errors.New("incoming record has invalid record MAC")
	RecordSequenceNumberOverflow = errors.New("maximum record sequence number reached")
	UnexpectedRecordContentType  = errors.New("incoming record has unexpected content type")
	WrongRecordVersion           = errors.New("incoming record has wrong protocol version")
	RecordTooLarge               = errors.New("incoming record exceeds maximum allowed record size")
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
