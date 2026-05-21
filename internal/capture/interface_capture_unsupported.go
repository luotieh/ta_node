//go:build !linux && !pcap

package capture

import (
	"fmt"

	"github.com/google/gopacket"
)

type InterfaceCapture struct{}

func NewInterfaceCapture(name string, snaplen int32, promiscuous bool, bpf string) (*InterfaceCapture, error) {
	return nil, fmt.Errorf("live capture without libpcap is currently supported on linux only")
}

func (c *InterfaceCapture) Packets() <-chan gopacket.Packet { return nil }

func (c *InterfaceCapture) Close() {}
