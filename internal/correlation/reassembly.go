package correlation

import "ta_node/internal/parser"

// Retain a bounded TCP sequence window including holes. Only the contiguous
// prefix is exposed; never concatenate payload across gaps. Signed deltas
// support sequence wraparound within this bounded (<2^31) window.
func (t *Tracker) reassemble(side *sideState, pf parser.PacketFeature) bool {
	seq := pf.TCPSeq
	if pf.TCPSYN {
		seq++
	}
	if !side.seqSet {
		side.baseSeq = seq
		side.seqSet = true
	}
	contiguous := len(side.payload)
	offset := int(int32(seq - side.baseSeq))
	if offset < 0 {
		prefix := -offset
		if prefix > t.opts.MaxOutOfOrderBytes || prefix+len(side.data) > t.opts.MaxReassemblyBytesPerSide {
			side.limited = true
			side.context.Truncated = true
			side.context.ReassemblyIncomplete = true
			return false
		}
		side.data = append(make([]byte, prefix), side.data...)
		side.present = append(make([]bool, prefix), side.present...)
		side.expectedEnd += prefix
		side.baseSeq = seq
		offset = 0
		contiguous = 0
	}
	if offset > contiguous && offset-contiguous > t.opts.MaxOutOfOrderBytes {
		side.limited = true
		side.context.Truncated = true
		side.context.ReassemblyIncomplete = true
		return false
	}
	expected := offset + len(pf.Payload)
	if pf.CapturedLen > 0 && pf.WireLen > pf.CapturedLen {
		expected += int(pf.WireLen - pf.CapturedLen)
	}
	if expected > side.expectedEnd {
		side.expectedEnd = expected
	}
	end := offset + len(pf.Payload)
	if end > t.opts.MaxReassemblyBytesPerSide {
		end = t.opts.MaxReassemblyBytesPerSide
		side.limited = true
		side.context.Truncated = true
	}
	if end > len(side.data) {
		side.data = append(side.data, make([]byte, end-len(side.data))...)
		side.present = append(side.present, make([]bool, end-len(side.present))...)
	}
	added := false
	for i := offset; i < end; i++ {
		value := pf.Payload[i-offset]
		if !side.present[i] {
			side.data[i] = value
			side.present[i] = true
			added = true
		} else if side.data[i] != value {
			side.limited = true
		}
	}
	n := contiguous
	for n < len(side.present) && side.present[n] {
		n++
	}
	side.payload = side.data[:n]
	side.context.ReassemblyIncomplete = side.limited || n < side.expectedEnd
	return !added && offset < end
}

func responseComplete(side *sideState) bool {
	return !side.context.Truncated && !side.context.ReassemblyIncomplete && httpMessageComplete(side.payload, true)
}
