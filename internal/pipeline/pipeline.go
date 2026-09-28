package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/fnv"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"ta_node/internal/capture"
	"ta_node/internal/correlation"
	"ta_node/internal/detector"
	"ta_node/internal/event"
	"ta_node/internal/evidence"
	"ta_node/internal/fingerprint"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
	"ta_node/internal/queue"
)

// queueSize bounds each worker's backlog. When full, the dispatcher stalls and
// backpressure reaches the capture source, mirroring the old serial loop's
// behavior of letting the kernel drop packets under overload.
const queueSize = 4096

// Deps carries the packet-processing collaborators shared by all workers.
// Every dependency is safe for concurrent use: aggregator/tracker/queue/counter
// lock internally, the detector and evidence writer keep no mutable shared
// state, and the matcher/engine read immutable rule sets.
type Deps struct {
	Fingerprints *fingerprint.Engine
	Intel        *intel.Matcher
	Flows        *flow.Aggregator
	Tracker      *correlation.Tracker // nil disables session aggregation
	Detector     *detector.Engine
	Evidence     *evidence.Writer
	Queue        queue.EventQueue
}

// Run dispatches packets from src across workers goroutines, keyed by a
// direction-insensitive flow hash so both directions of a conversation keep
// their packet order on a single worker. It returns after the source closes
// (draining the backlog) or after ctx is cancelled (dropping the backlog,
// matching the previous serial loop's shutdown semantics).
func Run(ctx context.Context, src capture.Source, d Deps, workers int) {
	if workers <= 0 {
		workers = 1
	}
	chans := make([]chan gopacket.Packet, workers)
	var wg sync.WaitGroup
	for i := range chans {
		chans[i] = make(chan gopacket.Packet, queueSize)
		wg.Add(1)
		go func(c <-chan gopacket.Packet) {
			defer wg.Done()
			for pkt := range c {
				if ctx.Err() != nil {
					continue
				}
				d.process(pkt)
			}
		}(chans[i])
	}

	packets := src.Packets()
dispatch:
	for {
		select {
		case <-ctx.Done():
			break dispatch
		case pkt, ok := <-packets:
			if !ok {
				break dispatch
			}
			w := chans[flowHash(pkt)%uint64(workers)]
			select {
			case w <- pkt:
			case <-ctx.Done():
				break dispatch
			}
		}
	}
	for _, c := range chans {
		close(c)
	}
	wg.Wait()

	if d.Tracker != nil {
		for _, ev := range d.Tracker.Flush() {
			if err := d.Queue.Enqueue(ev); err != nil {
				log.Printf("enqueue event context revision failed: %v", err)
			}
		}
	}
}

// process runs the full per-packet pipeline: parse, match, aggregate,
// correlate, detect, persist evidence, enqueue.
func (d *Deps) process(pkt gopacket.Packet) {
	pf, err := parser.Parse(pkt)
	if err != nil {
		return
	}
	fpHits := d.Fingerprints.Match(pf)
	intelHits := d.Intel.MatchPacket(pf)
	f := d.Flows.Update(pf, fpHits, intelHits)
	var observation correlation.Observation
	if d.Tracker != nil {
		observation = d.Tracker.Observe(pf, f.PacketSequence)
		for _, ev := range observation.Updates {
			if err := d.Queue.Enqueue(ev); err != nil {
				log.Printf("enqueue event context revision failed: %v", err)
			}
		}
	}
	if len(fpHits) == 0 && len(intelHits) == 0 {
		return
	}
	for _, ev := range d.Detector.Detect(f) {
		path, err := d.Evidence.Save(ev.EventID, pkt)
		if err != nil {
			log.Printf("save evidence failed: %v", err)
		}
		if path != "" {
			ev.EvidenceFile = path
		}
		if d.Tracker != nil {
			ev = d.Tracker.Register(observation, ev)
		}
		if err := d.Queue.Enqueue(ev); err != nil {
			log.Printf("enqueue event failed: %v", err)
		}
	}
}

// flowHash hashes the packet's 5-tuple with the same canonical endpoint
// ordering as flow.PairKey, so both directions of a conversation route to the
// same worker. Layers decoded here stay memoized on the lazy packet, so the
// worker's parser.Parse does not pay for them twice.
func flowHash(pkt gopacket.Packet) uint64 {
	var src, dst []byte
	var proto byte
	var sport, dport uint16
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		src, dst = ip4.SrcIP, ip4.DstIP
		proto = byte(ip4.Protocol)
	} else if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		src, dst = ip6.SrcIP, ip6.DstIP
		proto = byte(ip6.NextHeader)
	} else {
		// Non-IP traffic is dropped by the parser anyway; spread it by content.
		h := fnv.New64a()
		_, _ = h.Write(pkt.Data())
		return h.Sum64()
	}
	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		sport, dport = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		proto = 6
	} else if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		sport, dport = uint16(udp.SrcPort), uint16(udp.DstPort)
		proto = 17
	}
	if bytes.Compare(src, dst) > 0 || (bytes.Equal(src, dst) && sport > dport) {
		src, dst = dst, src
		sport, dport = dport, sport
	}
	h := fnv.New64a()
	_, _ = h.Write(src)
	_, _ = h.Write(dst)
	var tail [5]byte
	binary.BigEndian.PutUint16(tail[0:2], sport)
	binary.BigEndian.PutUint16(tail[2:4], dport)
	tail[4] = proto
	_, _ = h.Write(tail[:])
	return h.Sum64()
}

var _ = event.ThreatEvent{}
