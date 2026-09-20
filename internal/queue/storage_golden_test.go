// Run explicitly: go run -mod=vendor .analysis/queue_growth_repro.go
// Synthetic traffic only: no capture, network push, production files or DB writes.
package queue

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ta_node/internal/correlation"
	"ta_node/internal/detector"
	"ta_node/internal/event"
	"ta_node/internal/flow"
	"ta_node/internal/intel"
	"ta_node/internal/parser"
)

func TestSessionStorageGoldenAndDiskReduction(t *testing.T) {
	n := 20
	if os.Getenv("TA_STORAGE_BENCH") == "1" {
		n = 80
	}
	legacy, digest := runStorage(t, n, "legacy")
	compact, digest2 := runStorage(t, n, "v2")
	if digest != digest2 {
		t.Fatal("event sequence changed")
	}
	if n == 20 && digest != "45c82c628146ecc0cdae1b3096fadb9dd7db0381ba350ded6b83f6ac68be49d8" {
		t.Fatalf("legacy golden mismatch: %s", digest)
	}
	t.Logf("packets=%d legacy_disk=%d compact_disk=%d reduction=%.2f%%", n, legacy, compact, 100*(1-float64(compact)/float64(legacy)))
	if compact*10 > legacy {
		t.Fatal("disk reduction below 90% on high repetition fixture")
	}
}

func runStorage(t *testing.T, n int, backend string) (int64, string) {
	session := true
	path := filepath.Join(t.TempDir(), backend+".db")
	q, err := OpenSQLite(path, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	tracker := correlation.New(correlation.Options{StorePacketIndex: true, RevisionInterval: time.Microsecond})
	agg := flow.NewAggregator(100, time.Minute)
	det := detector.New("repro")
	hits := []intel.ThreatIntel{{ID: "test-ip", Type: "ip", Value: "203.0.113.9", Enabled: true, Severity: "high", Category: "c2"}}
	digest := sha256.New()
	rows, total, maxRow, rawBytes := 0, 0, 0, 0
	ids := map[string]bool{}
	record := func(ev event.ThreatEvent) {
		b, err := json.Marshal(ev)
		if err != nil {
			panic(err)
		}
		if err := q.Enqueue(ev); err != nil {
			t.Fatal(err)
		}
		digest.Write(b)
		digest.Write([]byte("\n"))
		rows++
		total += len(b)
		if len(b) > maxRow {
			maxRow = len(b)
		}
		ids[ev.EventID] = true
	}
	var seq uint32 = 100
	for i := 0; i < n; i++ {
		payload := bytes.Repeat([]byte("x"), 1024)
		direction := ""
		method := ""
		if i == 0 {
			payload = []byte("POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1000000\r\n\r\n")
			direction = "request"
			method = "POST"
		}
		raw := append(make([]byte, 54), payload...)
		pf := parser.PacketFeature{SrcIP: "192.0.2.1", DstIP: "203.0.113.9", SrcPort: 40000, DstPort: 80, Proto: "tcp", TCPSeq: seq,
			PacketTimeUsec: 1700000000000000 + uint64(i)*1000, Payload: payload, RawPacket: raw, CapturedLen: uint32(len(raw)), WireLen: uint32(len(raw)),
			MessageDirection: direction, HTTPMethod: method}
		seq += uint32(len(payload))
		rawBytes += len(raw)
		f := agg.Update(pf, nil, hits)
		var obs correlation.Observation
		if session {
			obs = tracker.Observe(pf, f.PacketSequence)
			for _, ev := range obs.Updates {
				record(ev)
			}
		}
		for _, ev := range det.Detect(f) {
			if session {
				ev = tracker.Register(obs, ev)
			}
			record(ev)
		}
	}
	if session {
		for _, ev := range tracker.Flush() {
			record(ev)
		}
	}
	mode := "packet"
	if session {
		mode = "session"
	}
	fmt.Printf("%s,%d,%d,%d,%d,%d,%d\n", mode, n, rawBytes, len(ids), rows, total, maxRow)
	t.Logf("digest=%x", digest.Sum(nil))
	pendingIDs, err := q.PendingIDs(rows + 1)
	if err != nil || len(pendingIDs) != rows {
		t.Fatalf("lost revisions: %d/%d %v", len(pendingIDs), rows, err)
	}
	restored := sha256.New()
	for _, id := range pendingIDs {
		ev, e := q.LoadEvent(id)
		if e != nil {
			t.Fatal(e)
		}
		b, e := json.Marshal(ev)
		if e != nil {
			t.Fatal(e)
		}
		restored.Write(b)
		restored.Write([]byte("\n"))
	}
	if fmt.Sprintf("%x", digest.Sum(nil)) != fmt.Sprintf("%x", restored.Sum(nil)) {
		t.Fatal("persisted event sequence differs")
	}
	if err = q.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size(), fmt.Sprintf("%x", digest.Sum(nil))
}
