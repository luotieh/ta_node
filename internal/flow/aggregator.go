package flow

import (
	"fmt"
	"sync"
	"time"

	"ta_node/internal/fingerprint"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
)

const (
	defaultMaxFlows    = 1_000_000
	defaultIdleTimeout = 120 * time.Second
)

// Aggregator tracks per-flow counters keyed by the 5-tuple. It bounds memory in
// two ways: idle flows are evicted by Cleanup (call it periodically), and the
// live flow count is capped at maxFlows. Hits are not accumulated on the stored
// flow — they are attached only to the value returned to the caller — so a
// long-lived, repeatedly-matching flow does not grow without bound.
type Aggregator struct {
	mu          sync.Mutex
	flows       map[string]*flowState
	maxFlows    int
	idleTimeout time.Duration
	now         func() time.Time
}

type flowState struct {
	feature  FlowFeature
	lastSeen time.Time
}

// NewAggregator builds an aggregator. Non-positive arguments fall back to sane
// defaults (1,000,000 flows / 120s idle timeout).
func NewAggregator(maxFlows int, idleTimeout time.Duration) *Aggregator {
	if maxFlows <= 0 {
		maxFlows = defaultMaxFlows
	}
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	return &Aggregator{
		flows:       map[string]*flowState{},
		maxFlows:    maxFlows,
		idleTimeout: idleTimeout,
		now:         time.Now,
	}
}

func (a *Aggregator) Update(pf parser.PacketFeature, fpHits []fingerprint.FingerprintHit, intelHits []intel.ThreatIntel) FlowFeature {
	key := fmt.Sprintf("%s:%d-%s:%d-%s", pf.SrcIP, pf.SrcPort, pf.DstIP, pf.DstPort, pf.Proto)
	a.mu.Lock()
	defer a.mu.Unlock()

	st := a.flows[key]
	if st == nil {
		if len(a.flows) >= a.maxFlows {
			a.cleanupLocked(a.now())
			if len(a.flows) >= a.maxFlows {
				// Still at capacity: return a transient, untracked feature so
				// detection still runs without letting the map grow.
				return transientFeature(pf, fpHits, intelHits)
			}
		}
		st = &flowState{feature: FlowFeature{
			FirstTime: pf.PacketTimeUsec,
			SrcIP:     pf.SrcIP,
			SrcPort:   pf.SrcPort,
			DstIP:     pf.DstIP,
			DstPort:   pf.DstPort,
			Proto:     pf.Proto,
		}}
		a.flows[key] = st
	}

	f := &st.feature
	f.LastTime = pf.PacketTimeUsec
	f.PacketTimeUsec = pf.PacketTimeUsec
	f.Packets++
	f.Bytes += uint64(len(pf.Payload))
	f.WireBytes += uint64(pf.WireLen)
	f.HTTPHost = firstNonEmpty(f.HTTPHost, pf.HTTPHost)
	f.HTTPURL = firstNonEmpty(f.HTTPURL, pf.HTTPURL)
	f.DNSQuery = firstNonEmpty(f.DNSQuery, pf.DNSQuery)
	f.EvidenceFile = firstNonEmpty(f.EvidenceFile, pf.EvidenceFile)
	st.lastSeen = a.now()

	out := st.feature
	out.FingerprintHits = fpHits
	out.IntelHits = intelHits
	attachAppContext(&out, pf)
	return out
}

// attachAppContext copies the triggering packet's application-layer context
// onto the returned feature. It is intentionally NOT written back to the stored
// flow: like hits, these (potentially large) fields must not accumulate on a
// long-lived flow, and the context that matters for an event is that of the
// packet that actually triggered the hit.
func attachAppContext(out *FlowFeature, pf parser.PacketFeature) {
	out.HTTPMethod = pf.HTTPMethod
	out.UserAgent = pf.UserAgent
	out.HTTPHeaders = pf.HTTPHeaders
	out.HTTPBodySample = pf.HTTPBodySample
	out.DNSQType = pf.DNSQType
	out.DNSAnswers = pf.DNSAnswers
	out.PayloadSample = pf.PayloadSample
	out.ICMPSeq = pf.ICMPSeq
	// HTTPHost/HTTPURL/DNSQuery already carried via firstNonEmpty on the stored
	// flow, but prefer the triggering packet's values when present.
	out.HTTPHost = firstNonEmpty(pf.HTTPHost, out.HTTPHost)
	out.HTTPURL = firstNonEmpty(pf.HTTPURL, out.HTTPURL)
	out.DNSQuery = firstNonEmpty(pf.DNSQuery, out.DNSQuery)
}

// Cleanup removes flows that have been idle for longer than the idle timeout
// and returns how many were evicted.
func (a *Aggregator) Cleanup() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cleanupLocked(a.now())
}

// Len reports the number of tracked flows.
func (a *Aggregator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.flows)
}

func (a *Aggregator) cleanupLocked(now time.Time) int {
	removed := 0
	for k, st := range a.flows {
		if now.Sub(st.lastSeen) >= a.idleTimeout {
			delete(a.flows, k)
			removed++
		}
	}
	return removed
}

func transientFeature(pf parser.PacketFeature, fpHits []fingerprint.FingerprintHit, intelHits []intel.ThreatIntel) FlowFeature {
	return FlowFeature{
		FirstTime:       pf.PacketTimeUsec,
		LastTime:        pf.PacketTimeUsec,
		PacketTimeUsec:  pf.PacketTimeUsec,
		SrcIP:           pf.SrcIP,
		SrcPort:         pf.SrcPort,
		DstIP:           pf.DstIP,
		DstPort:         pf.DstPort,
		Proto:           pf.Proto,
		Packets:         1,
		Bytes:           uint64(len(pf.Payload)),
		WireBytes:       uint64(pf.WireLen),
		HTTPHost:        pf.HTTPHost,
		HTTPURL:         pf.HTTPURL,
		DNSQuery:        pf.DNSQuery,
		EvidenceFile:    pf.EvidenceFile,
		FingerprintHits: fpHits,
		IntelHits:       intelHits,
	}
}

func firstNonEmpty(old, next string) string {
	if old != "" {
		return old
	}
	return next
}
