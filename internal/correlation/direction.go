package correlation

import (
	"bufio"
	"bytes"
	"net/http"

	"ta_node/internal/event"
	"ta_node/internal/parser"
)

// PacketDirection preserves explicit parser evidence without guessing by port.
func PacketDirection(pf parser.PacketFeature) event.DirectionAssessment {
	d := event.DirectionAssessment{MessageDirection: "unknown", DirectionSource: "unknown", DirectionConfidence: "unknown", TransportDirection: "unknown"}
	if pf.MessageDirection == "request" || pf.MessageDirection == "response" {
		d.MessageDirection = pf.MessageDirection
		d.DirectionSource, d.DirectionConfidence = "protocol", "high"
		if pf.Proto == "tcp" && pf.TCPSYN && pf.HTTPMethod == "" && pf.SNI == "" && !bytes.HasPrefix(pf.Payload, []byte("HTTP/")) {
			d.DirectionSource = "handshake"
		}
	}
	return d
}

func assessDirection(st *sessionState, pf parser.PacketFeature) event.DirectionAssessment {
	d := PacketDirection(pf)
	if pf.Proto != "tcp" {
		return d
	}
	candidate := ""
	if pf.TCPSYN {
		candidate = endpoint(pf.SrcIP, pf.SrcPort)
		if pf.TCPACK {
			candidate = endpoint(pf.DstIP, pf.DstPort)
		}
	} else if d.MessageDirection == "request" {
		candidate = endpoint(pf.SrcIP, pf.SrcPort)
	} else if d.MessageDirection == "response" {
		candidate = endpoint(pf.DstIP, pf.DstPort)
	}
	if candidate != "" {
		if st.directionClient == "" {
			st.directionClient = candidate
		} else if st.directionClient != candidate {
			st.directionConflict = true
		}
	}
	if st.directionClient != "" && !st.directionConflict {
		d.TransportDirection = "server_to_client"
		if endpoint(pf.SrcIP, pf.SrcPort) == st.directionClient {
			d.TransportDirection = "client_to_server"
		}
	}
	return d
}

// Only infer continuation inside a positively identified, length-framed HTTP
// message. Connection roles alone do not prove application request/response.
// This assessment is for the current occurrence; stored events are never edited.
func inferHTTPContinuation(d *event.DirectionAssessment, st *sessionState, tx *transactionState, pf parser.PacketFeature) {
	if pf.CapturedLen > 0 && pf.WireLen > pf.CapturedLen {
		return
	}
	if d.MessageDirection != "unknown" || st.directionConflict || st.directionClient == "" || len(pf.Payload) == 0 || pf.TCPSYN || pf.TCPFIN || pf.TCPRST {
		return
	}
	side, direction := &tx.response, "response"
	if endpoint(pf.SrcIP, pf.SrcPort) == st.directionClient {
		side, direction = &tx.request, "request"
	}
	if !side.seqSet || side.context.Truncated || side.limited {
		return
	}
	headEnd := bytes.Index(side.payload, []byte("\r\n\r\n"))
	if headEnd < 0 {
		return
	}
	r := bufio.NewReader(bytes.NewReader(side.payload[:headEnd+4]))
	var length int64
	if direction == "request" {
		msg, err := http.ReadRequest(r)
		if err != nil || len(msg.TransferEncoding) != 0 || msg.Header.Get("Upgrade") != "" || msg.Method == "CONNECT" {
			return
		}
		length = msg.ContentLength
	} else {
		// HEAD/CONNECT and upgrades do not obey an ordinary response body model.
		if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(tx.request.payload))); err == nil {
			if req.Method == "HEAD" || req.Method == "CONNECT" || req.Header.Get("Upgrade") != "" {
				return
			}
		}
		msg, err := http.ReadResponse(r, nil)
		if err != nil || len(msg.TransferEncoding) != 0 || msg.StatusCode == 101 {
			return
		}
		length = msg.ContentLength
	}
	if length <= 0 {
		return
	}
	offset := int64(int32(pf.TCPSeq - side.baseSeq))
	if offset < int64(headEnd+4) || offset+int64(len(pf.Payload)) > int64(headEnd+4)+length {
		return
	}
	d.MessageDirection, d.DirectionSource, d.DirectionConfidence = direction, "session", "medium"
}
