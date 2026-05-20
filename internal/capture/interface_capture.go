//go:build !pcap

package capture

import (
	"fmt"

	"github.com/google/gopacket"
)

type InterfaceCapture struct{}

func NewInterfaceCapture(name string, snaplen int32, promiscuous bool, bpf string) (*InterfaceCapture, error) {
	return nil, fmt.Errorf("live capture requires building with -tags pcap and system libpcap headers")
}

func (c *InterfaceCapture) Packets() <-chan gopacket.Packet { return nil }

func (c *InterfaceCapture) Close() {}
