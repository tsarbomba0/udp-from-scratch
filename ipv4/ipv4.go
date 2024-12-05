package ipv4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"pisa/util"
)

// Struct for an IP Header (No options)
type IPv4Header struct {
	HeaderLen       byte
	TotalLength     uint16
	Identification  uint16
	Flags           byte
	FragOffset      uint16
	TTL             byte
	Protocol        byte
	Checksum        uint16
	SourceAddr      []byte
	DestinationAddr []byte
}

// Turns a IPv4Header into []byte
func (h *IPv4Header) Marshal() []byte {
	totalLen := make([]byte, 2)
	binary.BigEndian.PutUint16(totalLen, h.TotalLength)

	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, h.Identification)

	fragOffset := make([]byte, 2)
	binary.BigEndian.PutUint16(fragOffset, h.FragOffset)

	buf := bytes.NewBuffer([]byte{69, 0})
	buf.WriteByte(h.HeaderLen)
	buf.Write(totalLen)
	buf.Write(id)
	buf.Write(h.Flags)
	buf.Write(fragOffset)
	buf.Write([]byte{h.TTL, h.Protocol})

	var b []byte
	if h.Checksum != nil {
		buf.Write(h.Checksum)
		buf.Write(h.SourceAddr)
		buf.Write(h.DestinationAddr)
		b = packetBuf.Bytes
	} else {
		buf.Write([]byte{0, 0})
		buf.Write(h.SourceAddr)
		buf.Write(h.DestinationAddr)
		// Checksum
		b = packetBuf.Bytes()

		checksumBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(checksumBytes, checksum(b))
		copy(b[10:12], checksumBytes)
	}

	return b

}

func DetermineLength(data []byte) uint16 {
	return uint16(len(data) + 24)
}

// Function to create packets
func CreatePacket(h *IPv4Header, data []byte) []byte {
	b = h.Marshal(h)

	return append(b, data...)
}

// Function to create packets "fast"
//
// Ignores stuff like identification, flags, fragmanting, diffserv or ecn.
func CreateFastPacket(h *IPv4Header, data []byte) []byte {
	packetBuf := bytes.NewBuffer([]byte{
		69, // Version + IHL
		0,  // DiffServ + ECN
	})

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)+24))

	packetBuf.Write(length)
	packetBuf.Write([]byte{
		0, 0, // identification
		0, 0, // flags and fragment offset
		h.TTL,
		h.Protocol,
		0, 0,
	})

	// addresses
	packetBuf.Write(h.SourceAddr)
	packetBuf.Write(h.DestinationAddr)

	// Checksum
	b := packetBuf.Bytes()

	checksumBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(checksumBytes, checksum(b))

	copy(b[10:12], checksumBytes)

	err := verifyChecksum(b)
	util.NonFatalError(err)

	return append(b, data...)
}

// Creates a Internet Checksum.
func checksum(header []byte) uint16 {
	var length int = len(header)
	var sum uint32
	for i := 0; i <= length-1; i += 2 {
		sum += uint32(header[i]) << 8
		sum += uint32(header[i+1])
	}
	return ^uint16(sum&0xffff + sum>>16)
}

// Verifies a checksum.
func verifyChecksum(header []byte) error {
	var length int = len(header)
	var sum uint32

	for i := 0; i <= length-1; i += 2 {
		sum += uint32(header[i]) << 8
		sum += uint32(header[i+1])
	}
	if length%2 == 1 {
		sum += uint32(header[length-1]) << 8
	}

	result := uint16(sum>>16 + sum&0xFFFF)
	if result == 0xFFFF {
		return nil
	} else {
		return fmt.Errorf("wrong checksum: %d", ^result)
	}
}
