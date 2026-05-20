//go:build pcap

package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type InterfaceCapture struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

func NewInterfaceCapture(name string, snaplen int32, promiscuous bool, bpf string) (*InterfaceCapture, error) {
	h, err := pcap.OpenLive(name, snaplen, promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if bpf != "" {
		if err := h.SetBPFFilter(bpf); err != nil {
			h.Close()
			return nil, err
		}
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	src.DecodeOptions.Lazy = true
	src.DecodeOptions.NoCopy = true
	return &InterfaceCapture{handle: h, source: src}, nil
}

func (c *InterfaceCapture) Packets() <-chan gopacket.Packet { return c.source.Packets() }

func (c *InterfaceCapture) Close() { c.handle.Close() }
