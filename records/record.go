package records

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

//type Record struct {
//	contentType ContentType
//	version     ProtocolVersion
//	length      uint16
//}
