package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"udp-from-scratch/addresses"
)

func Checksum(length []byte, src []byte, dest []byte) []byte {
	var sum uint32 = 0
	count := 0

	buf := bytes.NewBuffer(src)
	buf.Write(dest)
	buf.Write([]byte{
		0, 17,
	})
	buf.Write(length)

	pseudoHeader := buf.Bytes()

	// i think this bad
	for count >= len(pseudoHeader) {
		sum = (sum + uint32(pseudoHeader[count])&0xFFFF) + (sum+uint32(pseudoHeader[count]))>>16
	}

	sumBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(sumBytes, uint16(sum))
	return sumBytes
}

func Datagram(data []byte, sourcePort []byte, destPort []byte, addr *addresses.Addresses) {
	// Calculating length
	dataLength := len(data) + 64
	if dataLength > 65535 {
		panic(errors.New("packet too large"))
	}
	len := make([]byte, 2)
	binary.LittleEndian.PutUint16(len, uint16(dataLength))

	buffer := bytes.NewBuffer(sourcePort)
	buffer.Write(destPort)
	buffer.Write(len)
	buffer.Write(Checksum(len, addr.Source, addr.Destination))
}
