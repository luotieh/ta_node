package flow

import (
	"fmt"
	"sync"

	"ta_node/internal/fingerprint"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
)

type Aggregator struct {
	mu    sync.Mutex
	flows map[string]FlowFeature
}

func NewAggregator() *Aggregator {
	return &Aggregator{flows: map[string]FlowFeature{}}
}

func (a *Aggregator) Update(pf parser.PacketFeature, fpHits []fingerprint.FingerprintHit, intelHits []intel.ThreatIntel) FlowFeature {
	key := fmt.Sprintf("%s:%d-%s:%d-%s", pf.SrcIP, pf.SrcPort, pf.DstIP, pf.DstPort, pf.Proto)
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.flows[key]
	if f.FirstTime == 0 {
		f.FirstTime = pf.PacketTimeUsec
		f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Proto = pf.SrcIP, pf.SrcPort, pf.DstIP, pf.DstPort, pf.Proto
	}
	f.LastTime = pf.PacketTimeUsec
	f.PacketTimeUsec = pf.PacketTimeUsec
	f.Packets++
	f.Bytes += uint64(len(pf.Payload))
	f.HTTPHost = firstNonEmpty(f.HTTPHost, pf.HTTPHost)
	f.HTTPURL = firstNonEmpty(f.HTTPURL, pf.HTTPURL)
	f.DNSQuery = firstNonEmpty(f.DNSQuery, pf.DNSQuery)
	f.EvidenceFile = firstNonEmpty(f.EvidenceFile, pf.EvidenceFile)
	f.FingerprintHits = append(f.FingerprintHits, fpHits...)
	f.IntelHits = append(f.IntelHits, intelHits...)
	a.flows[key] = f
	return f
}

func firstNonEmpty(old, next string) string {
	if old != "" {
		return old
	}
	return next
}
