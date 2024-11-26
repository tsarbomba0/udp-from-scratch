package main

import (
	"net"
	"udp-from-scratch/addresses"
	"udp-from-scratch/ethernet"
	"udp-from-scratch/udp"
	"udp-from-scratch/util"
)

func main() {
	device, err := net.InterfaceByName("enp0s8")
	util.OnError(err)

	address := addresses.Addresses{
		Source:      addresses.ParseIP("192.168.0.1"),
		Destination: addresses.ParseIP("192.168.0.2"),
	}
	ethernet.SendEthernet([]byte("Versailles"), &address, &udp.PacketUDP{
		SrcPort:  67,
		DestPort: 68,
	}, *device, []byte{
		255, 255, 255, 255, 255, 255,
	})
}
