package ipv4

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Struct for an IP Header (No options)
type IPv4Header struct {
	HeaderLen       byte
	DSCPECN         byte
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

// Helper function to create the field for DSCP (6 bits) and ECN (2 bits)
func (h *IPv4Header) DSCPECN(dscp byte, ecn byte) (byte, error) {
	if dscp > 32 {
		return 0, fmt.Errorf("DSCP field can be set to 32 maximum.")
	} else if ecn > 3 {
		return 0, fmt.Errorf("ECN field can be set to 3 maximum")
	} else {
		return dscp + ecn
	}
}

// Turns a IPv4Header into []byte
func (h *IPv4Header) Marshal() []byte {

	totalLen := make([]byte, 2)
	binary.BigEndian.PutUint16(totalLen, h.TotalLength)

	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, h.Identification)

	fragOffset := make([]byte, 2)
	binary.BigEndian.PutUint16(fragOffset, h.FragOffset)

	buf := bytes.NewBuffer([]byte{64 + h.HeaderLen, h.DSCPECN})
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
func CreateFastPacket(ttl byte, proto byte, data []byte) []byte {
	header := &IPv4Header{
		HeaderLen:   5,
		DSCPECN:     0,
		TTL:         ttl,
		Protocol:    proto,
		TotalLength: DetermineLength(data),
	}
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
