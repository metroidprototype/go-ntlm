//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

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
	// Constuct Bytes based on https://msdn.microsoft.com/en-us/library/cc236641.aspx
	buffer := new(bytes.Buffer)
	// Signature (8 bytes)
	binary.Write(buffer, binary.LittleEndian, nm.Signature)

	// MessageType (4 bytes)
	binary.Write(buffer, binary.LittleEndian, nm.MessageType)

	// NegotiateFlags (4 bytes)
	binary.Write(buffer, binary.LittleEndian, nm.NegotiateFlags)

	// DomainNameFields (8 bytes)
	binary.Write(nm.DomainNameFields.Bytes())

	// WorkstationFields (8 bytes)
	binary.Write(nm.WorkstationFields.Bytes())

	// Version (8 bytes)
	binary.Write(m.Version.Bytes())

	// Add Payload (variable)
	binary.Write(buffer, binary.LittleEndian, nm.Payload)

	return buffer.Bytes()
}
