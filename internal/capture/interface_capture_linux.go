//go:build linux && !pcap

package capture

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

type InterfaceCapture struct {
	tpacket *afpacket.TPacket
	source  *gopacket.PacketSource
}

func NewInterfaceCapture(name string, snaplen int32, promiscuous bool, bpf string) (*InterfaceCapture, error) {
	if bpf != "" {
		return nil, fmt.Errorf("bpf_filter requires building with -tags pcap; AF_PACKET mode does not compile tcpdump filter strings")
	}
	if promiscuous {
		log.Printf("AF_PACKET capture does not switch interface %s to promiscuous mode; enable it externally if needed", name)
	}
	frameSize := int(snaplen)
	if frameSize < afpacket.DefaultFrameSize {
		frameSize = afpacket.DefaultFrameSize
	}
	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(name),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(frameSize*128),
		afpacket.OptNumBlocks(128),
		afpacket.OptBlockTimeout(64*time.Millisecond),
		afpacket.OptPollTimeout(-1*time.Millisecond),
	)
	if err != nil {
		return nil, err
	}
	src := gopacket.NewPacketSource(tp, layers.LinkTypeEthernet)
	src.DecodeOptions.Lazy = true
	src.DecodeOptions.NoCopy = true
	return &InterfaceCapture{tpacket: tp, source: src}, nil
}

func (c *InterfaceCapture) Packets() <-chan gopacket.Packet { return c.source.Packets() }

func (c *InterfaceCapture) Close() { c.tpacket.Close() }
