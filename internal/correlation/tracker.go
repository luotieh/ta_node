package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/parser"
)

type Options struct {
	MaxSessions               int
	MaxTransactionsPerSession int
	MaxPacketsPerTransaction  int
	MaxReassemblyBytesPerSide int
	MaxOutOfOrderBytes        int
	ResponseWait              time.Duration
	SessionIdleTimeout        time.Duration
	StorePacketIndex          bool
	// RevisionInterval throttles non-final context revisions: after the first
	// update, further updates are emitted at most once per interval so an
	// active long-lived flow does not produce one push per payload packet.
	// Final revisions (connection close / flush) are always emitted.
	RevisionInterval time.Duration
}

type Observation struct {
	SessionID      string
	TransactionID  string
	Exchange       *event.ExchangeContext
	SessionSummary *event.SessionSummary
	ContextFinal   bool
	Updates        []event.ThreatEvent
}

type Tracker struct {
	mu          sync.Mutex
	opts        Options
	sessions    map[string]*sessionState
	lastCleanup uint64
}

type sessionState struct {
	key          string
	id           string
	firstUsec    uint64
	lastUsec     uint64
	endpointA    string
	endpointB    string
	client       string
	midstream    bool
	aPackets     uint64
	bPackets     uint64
	aWireBytes   uint64
	bWireBytes   uint64
	hitCount     uint64
	nextTxn      uint64
	transactions []*transactionState
}

type transactionState struct {
	id             string
	lastUsec       uint64
	lastReviseUsec uint64
	request        sideState
	response       sideState
	events         map[string]event.ThreatEvent
	final          bool
}

type sideState struct {
	context event.ExchangeMessageContext
	payload []byte
	seen    map[string]bool
	nextSeq uint32
	seqSet  bool
}

func New(opts Options) *Tracker {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 100000
	}
	if opts.MaxTransactionsPerSession <= 0 {
		opts.MaxTransactionsPerSession = 16
	}
	if opts.MaxPacketsPerTransaction <= 0 {
		opts.MaxPacketsPerTransaction = 128
	}
	if opts.MaxReassemblyBytesPerSide <= 0 {
		opts.MaxReassemblyBytesPerSide = 256 * 1024
	}
	if opts.MaxOutOfOrderBytes <= 0 {
		opts.MaxOutOfOrderBytes = 64 * 1024
	}
	if opts.ResponseWait <= 0 {
		opts.ResponseWait = 30 * time.Second
	}
	if opts.SessionIdleTimeout <= 0 {
		opts.SessionIdleTimeout = 120 * time.Second
	}
	if opts.RevisionInterval <= 0 {
		opts.RevisionInterval = 10 * time.Second
	}
	return &Tracker{opts: opts, sessions: map[string]*sessionState{}}
}

// Observe records one packet and returns both its current transaction context
// and any higher-revision events made possible by this packet.
func (t *Tracker) Observe(pf parser.PacketFeature, packetSequence uint64) Observation {
	t.mu.Lock()
	defer t.mu.Unlock()

	var updates []event.ThreatEvent
	updates = append(updates, t.cleanupLocked(pf.PacketTimeUsec)...)
	key, endpointA, endpointB, sourceIsA := canonicalKey(pf)
	st := t.sessions[key]
	if st != nil && pf.Proto == "tcp" && pf.TCPSYN && !pf.TCPACK {
		updates = append(updates, t.finalizeSession(st, "not_captured")...)
		delete(t.sessions, key)
		st = nil
	}
	if st == nil {
		if len(t.sessions) >= t.opts.MaxSessions {
			oldestKey, oldest := t.oldestSession()
			if oldest != nil {
				updates = append(updates, t.finalizeSession(oldest, "not_captured")...)
				delete(t.sessions, oldestKey)
			}
		}
		st = &sessionState{
			key:       key,
			id:        stableID("ses", key, strconv.FormatUint(pf.PacketTimeUsec, 10)),
			firstUsec: pf.PacketTimeUsec,
			lastUsec:  pf.PacketTimeUsec,
			endpointA: endpointA,
			endpointB: endpointB,
			midstream: !(pf.Proto == "tcp" && pf.TCPSYN && !pf.TCPACK),
		}
		if pf.Proto == "tcp" && pf.TCPSYN && !pf.TCPACK {
			st.client = endpoint(pf.SrcIP, pf.SrcPort)
		}
		t.sessions[key] = st
	}

	st.lastUsec = max64(st.lastUsec, pf.PacketTimeUsec)
	if sourceIsA {
		st.aPackets++
		st.aWireBytes += uint64(pf.WireLen)
	} else {
		st.bPackets++
		st.bWireBytes += uint64(pf.WireLen)
	}

	var tx *transactionState
	source := endpoint(pf.SrcIP, pf.SrcPort)
	switch {
	case pf.Proto == "tcp" && pf.MessageDirection == "request":
		st.client = source
		tx = t.newTransaction(st, pf.PacketTimeUsec)
		t.appendSide(&tx.request, pf, packetSequence)
	case pf.Proto == "tcp" && pf.MessageDirection == "response":
		if st.client == "" {
			st.client = endpoint(pf.DstIP, pf.DstPort)
		}
		tx = t.responseTransaction(st, pf.PacketTimeUsec)
		t.appendSide(&tx.response, pf, packetSequence)
		if httpMessageComplete(tx.response.payload, true) {
			tx.final = true
		}
	case pf.Proto == "tcp" && len(pf.Payload) > 0:
		tx = t.continuationTransaction(st, source)
		if tx != nil {
			if st.client != "" && source == st.client && tx.response.context.PacketCount == 0 {
				t.appendSide(&tx.request, pf, packetSequence)
			} else {
				t.appendSide(&tx.response, pf, packetSequence)
				if httpMessageComplete(tx.response.payload, true) {
					tx.final = true
				}
			}
		}
	}

	if pf.Proto == "tcp" && (pf.TCPFIN || pf.TCPRST) {
		for _, candidate := range st.transactions {
			if !candidate.final {
				candidate.final = true
			}
			updates = append(updates, t.reviseTransaction(st, candidate)...)
		}
	} else if tx != nil {
		tx.lastUsec = pf.PacketTimeUsec
		updates = append(updates, t.reviseTransaction(st, tx)...)
	}

	obs := Observation{SessionID: st.id, SessionSummary: t.summary(st), Updates: updates}
	if tx != nil {
		obs.TransactionID = tx.id
		obs.Exchange = t.exchange(tx)
		obs.ContextFinal = tx.final
	}
	return obs
}

// Register enriches a newly detected occurrence and retains a bounded copy so
// a later response can emit a higher-revision snapshot of the same event.
func (t *Tracker) Register(obs Observation, ev event.ThreatEvent) event.ThreatEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	ev.SessionID = obs.SessionID
	ev.TransactionID = obs.TransactionID
	ev.ContextRevision = 1
	ev.ContextFinal = obs.ContextFinal
	ev.Exchange = cloneExchange(obs.Exchange)
	ev.SessionSummary = cloneSummary(obs.SessionSummary)
	st, tx := t.findTransaction(obs.SessionID, obs.TransactionID)
	if st == nil {
		return ev
	}
	st.hitCount++
	ev.SessionSummary = t.summary(st)
	if tx != nil {
		applyLegacyExchange(&ev, ev.Exchange)
		tx.events[ev.EventID] = cloneEvent(ev)
	}
	return ev
}

// Flush finalizes all pending contexts. It is used when an offline PCAP ends or
// the node shuts down, ensuring pending request events receive a final status.
func (t *Tracker) Flush() []event.ThreatEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	var updates []event.ThreatEvent
	for key, st := range t.sessions {
		updates = append(updates, t.finalizeSession(st, "not_captured")...)
		delete(t.sessions, key)
	}
	return updates
}

func (t *Tracker) newTransaction(st *sessionState, usec uint64) *transactionState {
	if len(st.transactions) >= t.opts.MaxTransactionsPerSession {
		remove := 0
		for i, tx := range st.transactions {
			if tx.final {
				remove = i
				break
			}
		}
		st.transactions = append(st.transactions[:remove], st.transactions[remove+1:]...)
	}
	st.nextTxn++
	tx := &transactionState{
		id:       stableID("txn", st.id, strconv.FormatUint(st.nextTxn, 10)),
		lastUsec: usec,
		events:   map[string]event.ThreatEvent{},
	}
	st.transactions = append(st.transactions, tx)
	return tx
}

func (t *Tracker) responseTransaction(st *sessionState, usec uint64) *transactionState {
	for _, tx := range st.transactions {
		if !tx.final {
			return tx
		}
	}
	return t.newTransaction(st, usec)
}

func (t *Tracker) continuationTransaction(st *sessionState, source string) *transactionState {
	if st.client != "" && source == st.client {
		for i := len(st.transactions) - 1; i >= 0; i-- {
			tx := st.transactions[i]
			if !tx.final && tx.response.context.PacketCount == 0 {
				return tx
			}
		}
		return nil
	}
	for _, tx := range st.transactions {
		if !tx.final {
			return tx
		}
	}
	return nil
}

func (t *Tracker) appendSide(side *sideState, pf parser.PacketFeature, packetSequence uint64) {
	if side.seen == nil {
		side.seen = map[string]bool{}
	}
	key := fmt.Sprintf("%d:%d", pf.TCPSeq, len(pf.Payload))
	retransmission := side.seen[key]
	side.context.PacketCount++
	side.context.CapturedBytes += uint64(pf.CapturedLen)
	side.context.WireBytes += uint64(pf.WireLen)
	if side.context.CaptureStartTimeUsec == 0 {
		side.context.CaptureStartTimeUsec = pf.PacketTimeUsec
	}
	side.context.CaptureEndTimeUsec = pf.PacketTimeUsec
	if retransmission {
		side.context.Retransmissions++
	} else {
		side.seen[key] = true
		if len(pf.Payload) > 0 {
			if side.seqSet {
				switch {
				case pf.TCPSeq < side.nextSeq:
					retransmission = true
					side.context.Retransmissions++
				case pf.TCPSeq > side.nextSeq:
					gap := uint64(pf.TCPSeq - side.nextSeq)
					side.context.ReassemblyIncomplete = true
					if gap > uint64(t.opts.MaxOutOfOrderBytes) {
						side.context.Truncated = true
					}
				}
			}
			if !retransmission {
				remaining := t.opts.MaxReassemblyBytesPerSide - len(side.payload)
				if remaining > 0 {
					chunk := pf.Payload
					if len(chunk) > remaining {
						chunk = chunk[:remaining]
						side.context.Truncated = true
					}
					side.payload = append(side.payload, chunk...)
				} else {
					side.context.Truncated = true
				}
				end := pf.TCPSeq + uint32(len(pf.Payload))
				if !side.seqSet || end > side.nextSeq {
					side.nextSeq = end
					side.seqSet = true
				}
			}
		}
	}
	if t.opts.StorePacketIndex && len(side.context.Packets) < t.opts.MaxPacketsPerTransaction {
		wireLen := pf.WireLen
		if wireLen < pf.CapturedLen {
			wireLen = pf.CapturedLen
		}
		side.context.Packets = append(side.context.Packets, event.RawMessageContext{
			CaptureTime:      eventTime(pf.PacketTimeUsec),
			CaptureTimeUsec:  pf.PacketTimeUsec,
			PacketSequence:   packetSequence,
			PacketHex:        hex.EncodeToString(pf.RawPacket),
			PayloadHex:       hex.EncodeToString(pf.Payload),
			PayloadText:      parser.PayloadText(pf.Payload),
			CapturedLength:   pf.CapturedLen,
			WireLength:       wireLen,
			CaptureTruncated: pf.CapturedLen > 0 && wireLen > pf.CapturedLen,
			TCPSeq:           pf.TCPSeq,
			TCPAck:           pf.TCPAck,
			Retransmission:   retransmission,
		})
	} else if t.opts.StorePacketIndex {
		side.context.Truncated = true
	}
}

func (t *Tracker) exchange(tx *transactionState) *event.ExchangeContext {
	if tx == nil {
		return nil
	}
	ex := &event.ExchangeContext{ResponseStatus: "pending"}
	if tx.request.context.PacketCount > 0 {
		ex.Request = snapshotSide(&tx.request)
	}
	if tx.response.context.PacketCount > 0 {
		ex.Response = snapshotSide(&tx.response)
		ex.ResponseStatus = "complete"
	} else if tx.final {
		ex.ResponseStatus = "not_captured"
	}
	return ex
}

func snapshotSide(side *sideState) *event.ExchangeMessageContext {
	out := side.context
	out.ReassembledHex = hex.EncodeToString(side.payload)
	out.ReassembledText = parser.PayloadText(side.payload)
	out.Packets = append([]event.RawMessageContext(nil), side.context.Packets...)
	return &out
}

func (t *Tracker) reviseTransaction(st *sessionState, tx *transactionState) []event.ThreatEvent {
	if tx == nil || len(tx.events) == 0 {
		return nil
	}
	if !tx.final && tx.lastReviseUsec != 0 && tx.lastUsec-tx.lastReviseUsec < uint64(t.opts.RevisionInterval.Microseconds()) {
		return nil
	}
	tx.lastReviseUsec = tx.lastUsec
	var updates []event.ThreatEvent
	sharedExchange := t.exchange(tx)
	sharedSummary := t.summary(st)
	for id, stored := range tx.events {
		stored = cloneEvent(stored)
		stored.ContextRevision++
		stored.ContextFinal = tx.final
		stored.Exchange = sharedExchange
		stored.SessionSummary = sharedSummary
		applyLegacyExchange(&stored, stored.Exchange)
		tx.events[id] = cloneEvent(stored)
		updates = append(updates, stored)
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].EventID < updates[j].EventID })
	return updates
}

func (t *Tracker) finalizeSession(st *sessionState, missingStatus string) []event.ThreatEvent {
	var updates []event.ThreatEvent
	for _, tx := range st.transactions {
		if !tx.final {
			tx.final = true
		}
		if tx.response.context.PacketCount == 0 && missingStatus != "" {
			// exchange() derives not_captured from final + empty response.
		}
		updates = append(updates, t.reviseTransaction(st, tx)...)
	}
	return updates
}

func (t *Tracker) cleanupLocked(nowUsec uint64) []event.ThreatEvent {
	if nowUsec == 0 {
		return nil
	}
	if t.lastCleanup != 0 && nowUsec >= t.lastCleanup && nowUsec-t.lastCleanup < 1_000_000 {
		return nil
	}
	t.lastCleanup = nowUsec
	var updates []event.ThreatEvent
	waitUsec := uint64(t.opts.ResponseWait / time.Microsecond)
	idleUsec := uint64(t.opts.SessionIdleTimeout / time.Microsecond)
	for key, st := range t.sessions {
		for _, tx := range st.transactions {
			if !tx.final && nowUsec >= tx.lastUsec && nowUsec-tx.lastUsec >= waitUsec {
				tx.final = true
				updates = append(updates, t.reviseTransaction(st, tx)...)
			}
		}
		if nowUsec >= st.lastUsec && nowUsec-st.lastUsec >= idleUsec {
			updates = append(updates, t.finalizeSession(st, "not_captured")...)
			delete(t.sessions, key)
		}
	}
	return updates
}

func (t *Tracker) oldestSession() (string, *sessionState) {
	var key string
	var oldest *sessionState
	for candidateKey, st := range t.sessions {
		if oldest == nil || st.lastUsec < oldest.lastUsec {
			key, oldest = candidateKey, st
		}
	}
	return key, oldest
}

func (t *Tracker) findTransaction(sessionID, transactionID string) (*sessionState, *transactionState) {
	for _, st := range t.sessions {
		if st.id != sessionID {
			continue
		}
		if transactionID == "" {
			return st, nil
		}
		for _, tx := range st.transactions {
			if tx.id == transactionID {
				return st, tx
			}
		}
		return st, nil
	}
	return nil, nil
}

func (t *Tracker) summary(st *sessionState) *event.SessionSummary {
	summary := &event.SessionSummary{
		FirstTimeUsec: st.firstUsec,
		LastTimeUsec:  st.lastUsec,
		HitCount:      st.hitCount,
		Midstream:     st.midstream,
	}
	if st.client == st.endpointB {
		summary.ClientPackets, summary.ServerPackets = st.bPackets, st.aPackets
		summary.ClientWireBytes, summary.ServerWireBytes = st.bWireBytes, st.aWireBytes
	} else {
		summary.ClientPackets, summary.ServerPackets = st.aPackets, st.bPackets
		summary.ClientWireBytes, summary.ServerWireBytes = st.aWireBytes, st.bWireBytes
	}
	return summary
}

func canonicalKey(pf parser.PacketFeature) (string, string, string, bool) {
	a := endpoint(pf.SrcIP, pf.SrcPort)
	b := endpoint(pf.DstIP, pf.DstPort)
	sourceIsA := true
	if b < a {
		a, b = b, a
		sourceIsA = false
	}
	return strings.ToLower(pf.Proto) + "|" + a + "|" + b, a, b, sourceIsA
}

func endpoint(ip string, port uint16) string {
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func stableID(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return prefix + "-" + hex.EncodeToString(sum[:16])
}

func eventTime(usec uint64) string {
	if usec == 0 {
		return ""
	}
	return time.UnixMicro(int64(usec)).UTC().Format(time.RFC3339Nano)
}

func httpMessageComplete(payload []byte, response bool) bool {
	text := string(payload)
	headerEnd := strings.Index(text, "\r\n\r\n")
	if headerEnd < 0 {
		return false
	}
	head := text[:headerEnd]
	body := text[headerEnd+4:]
	lower := strings.ToLower(head)
	if strings.Contains(lower, "transfer-encoding: chunked") {
		return strings.HasSuffix(body, "\r\n0\r\n\r\n") || body == "0\r\n\r\n"
	}
	for _, line := range strings.Split(head, "\r\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "content-length") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		return err == nil && len(body) >= n
	}
	if response {
		first, _, _ := strings.Cut(head, "\r\n")
		parts := strings.Fields(first)
		if len(parts) >= 2 && (strings.HasPrefix(parts[1], "1") || parts[1] == "204" || parts[1] == "304") {
			return true
		}
		return false
	}
	return true
}

func applyLegacyExchange(ev *event.ThreatEvent, ex *event.ExchangeContext) {
	if ev.RawPacket == nil || ex == nil {
		return
	}
	if ex.Request != nil && len(ex.Request.Packets) > 0 {
		request := ex.Request.Packets[0]
		ev.RawPacket.Request = &request
	}
	if ex.Response != nil && len(ex.Response.Packets) > 0 {
		response := ex.Response.Packets[0]
		ev.RawPacket.Response = &response
	}
}

// Internal events are immutable after publication. Copy only mutable wrappers;
// strings and immutable application/IOC structures can be shared safely.
func cloneEvent(in event.ThreatEvent) event.ThreatEvent {
	out := in
	if in.RawPacket != nil {
		raw := *in.RawPacket
		out.RawPacket = &raw
	}
	out.Exchange = cloneExchange(in.Exchange)
	out.SessionSummary = cloneSummary(in.SessionSummary)
	return out
}
func cloneExchange(in *event.ExchangeContext) *event.ExchangeContext {
	if in == nil {
		return nil
	}
	out := *in
	if in.Request != nil {
		side := *in.Request
		out.Request = &side
	}
	if in.Response != nil {
		side := *in.Response
		out.Response = &side
	}
	return &out
}

func cloneSummary(in *event.SessionSummary) *event.SessionSummary {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
