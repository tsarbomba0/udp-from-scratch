package ipv4

import (
	"bytes"
	"encoding/binary"
)

// Type to define Source and Destination address
type Addresses struct {
	Source      []byte
	Destination []byte
}

// Function to calculate the IP checksum
func IPChecksum(header []byte) []byte {
	var sum uint32 = 0
	var count int = 0
	var sumBytes []byte = make([]byte, 2)

	for count > len(header)-1 {
		sum = sum + uint32(header[count])
		count++
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + sum>>16
	}

	binary.LittleEndian.PutUint16(sumBytes, uint16(^sum))

	return sumBytes

}

// Creates a IP Packet
func Packet(data []byte, ttl uint8, protocol uint8, addr *Addresses) []byte {
	buf := bytes.NewBuffer([]byte{
		115, // Version + IHL
		0,   // DiffServ + ECN
	})

	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len(data)))

	// length
	buf.Write(length)

	buf.Write([]byte{
		0, 0, // indentification, not used here
		0, 0, // flags 3 bits fragment offset 13 bits
		ttl,      // ttl
		protocol, // udp is 17
	})

	// at first a empty checksum field, later filled out
	buf.Write(make([]byte, 2))

	// Source and destination address
	buf.Write(addr.Source)
	buf.Write(addr.Destination)

	// Checksum
	b := buf.Bytes()
	checksum := IPChecksum(b)
	copy(b[8:10], checksum)

	return append(b, data...)
}
