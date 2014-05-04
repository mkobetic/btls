package records

type ProtocolVersion uint16

const (
	SSL30 ProtocolVersion = 0x0300
	TLS10 ProtocolVersion = 0x0301
	TLS11 ProtocolVersion = 0x0302
	TLS12 ProtocolVersion = 0x0303
)

type ContentType uint8

const (
	change_cipher_spec ContentType = 20
	alert              ContentType = 21
	handshake          ContentType = 22
	application_data   ContentType = 23
)

const (
	headerSize          = 5
	maxPlaintextLength  = 1 << 14
	maxCompressedLength = maxPlaintextLength + 1024
	maxCiphertextLength = maxCompressedLength + 1024
)

//type Record struct {
//	contentType ContentType
//	version     ProtocolVersion
//	length      uint16
//}
