//go:build linux && !pcap

package capture

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type InterfaceCapture struct {
	fd     int
	source *gopacket.PacketSource
}

type rawPacketSource struct {
	fd         int
	ifaceIndex int
	buf        []byte
}

func NewInterfaceCapture(name string, snaplen int32, promiscuous bool, bpf string) (*InterfaceCapture, error) {
	if bpf != "" {
		return nil, fmt.Errorf("bpf_filter requires building with -tags pcap; AF_PACKET mode does not compile tcpdump filter strings")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	if snaplen <= 0 {
		snaplen = 65535
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if promiscuous {
		err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		})
		if err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}

	packetSource := &rawPacketSource{
		fd:         fd,
		ifaceIndex: iface.Index,
		buf:        make([]byte, int(snaplen)),
	}
	src := gopacket.NewPacketSource(packetSource, layers.LinkTypeEthernet)
	src.DecodeOptions.Lazy = true
	return &InterfaceCapture{fd: fd, source: src}, nil
}

func (c *InterfaceCapture) Packets() <-chan gopacket.Packet { return c.source.Packets() }

func (c *InterfaceCapture) Close() { _ = unix.Close(c.fd) }

func (s *rawPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		n, _, err := unix.Recvfrom(s.fd, s.buf, unix.MSG_TRUNC)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		// MSG_TRUNC returns the original frame length even when the buffer is shorter.
		captured := n
		if captured > len(s.buf) {
			captured = len(s.buf)
		}
		data := append([]byte(nil), s.buf[:captured]...)
		info := packetCaptureInfo(captured, n, s.ifaceIndex)
		info.Timestamp = time.Now()
		return data, info, nil
	}
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
