package capture

import "github.com/google/gopacket"

type Source interface {
	Packets() <-chan gopacket.Packet
	Close()
}

// packetCaptureInfo keeps the received byte count distinct from the original frame length.
func packetCaptureInfo(captured, original, iface int) gopacket.CaptureInfo {
	if original < captured {
		original = captured
	}
	return gopacket.CaptureInfo{CaptureLength: captured, Length: original, InterfaceIndex: iface}
}
