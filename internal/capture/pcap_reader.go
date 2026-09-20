package capture

import (
	"io"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type PCAPReader struct {
	file      *os.File
	reader    *pcapgo.Reader
	out       chan gopacket.Packet
	closeOnce sync.Once
}

func NewPCAPReader(path, bpf string) (*PCAPReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	pr := &PCAPReader{file: f, reader: r, out: make(chan gopacket.Packet, 128)}
	go pr.readLoop()
	return pr, nil
}

func (r *PCAPReader) readLoop() {
	defer r.closeFile()
	defer close(r.out)
	for {
		data, ci, err := r.reader.ReadPacketData()
		if err == io.EOF {
			return
		}
		if err != nil {
			return
		}
		pkt := gopacket.NewPacket(data, r.reader.LinkType(), gopacket.Default)
		pkt.Metadata().CaptureInfo = ci
		r.out <- pkt
	}
}

func (r *PCAPReader) Packets() <-chan gopacket.Packet { return r.out }

func (r *PCAPReader) Close() {
	r.closeOnce.Do(func() {
		r.closeFile()
	})
}

func (r *PCAPReader) closeFile() {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
}
