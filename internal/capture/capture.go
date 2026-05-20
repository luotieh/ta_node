package capture

import "github.com/google/gopacket"

type Source interface {
	Packets() <-chan gopacket.Packet
	Close()
}
