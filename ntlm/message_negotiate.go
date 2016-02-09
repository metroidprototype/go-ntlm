//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
)

type NegotiateMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

func (n *NegotiateMessage) Bytes() []byte {
	payloadLen := int(n.DomainNameFields.Len + n.WorkstationFields.Len)

	messageBytes := make([]byte, 0, n.PayloadOffset+payloadLen)
	// Constuct Bytes based on https://msdn.microsoft.com/en-us/library/cc236641.aspx
	buffer := bytes.NewBuffer(messageBytes)

	buffer.Write(n.Signature)

	binary.Write(buffer, binary.LittleEndian, n.MessageType)

	binary.Write(buffer, binary.LittleEndian, n.NegotiateFlags)

	buffer.Write(n.DomainNameFields.Bytes())

	buffer.Write(n.WorkstationFields.Bytes())

	buffer.Write(n.Version.Bytes())

	buffer.Write(n.Payload)

	return buffer.Bytes()
}
