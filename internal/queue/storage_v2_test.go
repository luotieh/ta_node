package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ta_node/internal/event"
)

func richEvent(id string, revision uint64) event.ThreatEvent {
	raw := strings.Repeat("GET / HTTP/1.1\r\n", 100)
	return event.ThreatEvent{EventID: id, EventTime: 18446744073709551615, ContextRevision: revision, SrcIP: "192.0.2.1", RawFeature: map[string]any{"string": "00123", "null": nil, "list": []string{}, "uint": uint64(18446744073709551615)},
		RawPacket: &event.RawPacketContext{PacketHex: hex.EncodeToString([]byte(raw)), PayloadHex: hex.EncodeToString([]byte(raw)), PayloadText: raw},
		Exchange:  &event.ExchangeContext{Request: &event.ExchangeMessageContext{ReassembledHex: hex.EncodeToString([]byte(raw)), ReassembledText: raw, Packets: []event.RawMessageContext{{PacketHex: hex.EncodeToString([]byte(raw)), PayloadText: raw}}}}}
}
func TestContentRoundTripAndDedup(t *testing.T) {
	q, err := NewSQLite(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	// SQLite INTEGER timestamp must fit signed int64; large uint64 elsewhere must remain exact.
	ev := richEvent("a", 1)
	ev.EventTime = 1700000000000000
	if err = q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	var first int
	q.db.QueryRow("SELECT count(*) FROM queue_content").Scan(&first)
	if err = q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	var second int
	q.db.QueryRow("SELECT count(*) FROM queue_content").Scan(&second)
	if first != second {
		t.Fatal("duplicate enqueue created content")
	}
	original, _ := json.Marshal(ev)
	var payload string
	q.db.QueryRow("SELECT payload FROM event_queue").Scan(&payload)
	restored, err := decodePayload(q.db, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(original, restored) {
		t.Fatalf("roundtrip mismatch\n%s\n%s", original, restored)
	}
	ev.ContextRevision = 2
	if err = q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	q.db.QueryRow("SELECT count(*) FROM queue_content").Scan(&second)
	if second-first > 3 {
		t.Fatalf("unchanged evidence duplicated: %d new nodes", second-first)
	}
	// Corruption is surfaced, never substituted with empty evidence.
	root, err := payloadRoot(payload)
	if err != nil {
		t.Fatal(err)
	}
	q.db.Exec("UPDATE queue_content SET data=x'00' WHERE hash=?", root)
	if _, err = q.LoadEvent(1); err == nil {
		t.Fatal("corruption was accepted")
	}
}
func TestArchivePreservesQueriesAndSharedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.db")
	q, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for _, id := range []string{"a", "b"} {
		ev := richEvent(id, 1)
		ev.EventTime = 1
		if err = q.Enqueue(ev); err != nil {
			t.Fatal(err)
		}
	}
	q.MarkPushed("a", 1)
	n, err := q.Archive(context.Background(), filepath.Join(dir, "archive"), time.Now().Add(time.Hour), 10)
	if err != nil || n != 1 {
		t.Fatalf("archive %d %v", n, err)
	}
	if _, err = q.Collect(10000); err != nil {
		t.Fatal(err)
	}
	pending, err := q.LoadPending(10)
	if err != nil || len(pending) != 1 || pending[0].EventID != "b" {
		t.Fatalf("pending %v %v", pending, err)
	}
	archived, err := ReadEvent(path, "a")
	if err != nil || archived.RawPacket == nil {
		t.Fatalf("read archive %v", err)
	}
	if err = q.Enqueue(archived); err != nil {
		t.Fatal(err)
	}
	var count int
	q.db.QueryRow("SELECT count(*) FROM event_queue").Scan(&count)
	if count != 1 {
		t.Fatal("archived event duplicated")
	}
	logs, err := RecentPushLogs(path, 10)
	if err != nil || len(logs) != 2 {
		t.Fatalf("logs %d %v", len(logs), err)
	}
	if logs[0].EventID != "b" || logs[1].Status != "pushed" {
		t.Fatalf("log ordering/state %+v", logs)
	}
	// An unavailable target cannot consume acknowledged source records.
	q.MarkPushed("b", 1)
	bad := filepath.Join(dir, "not-a-directory")
	os.WriteFile(bad, []byte("x"), 0600)
	if _, err = q.Archive(context.Background(), bad, time.Now().Add(time.Hour), 10); err == nil {
		t.Fatal("expected archive error")
	}
	if _, err = q.LoadEvent(2); err != nil {
		t.Fatal("failed archive removed source", err)
	}
}
func TestFrozenMigrationResumeAndRollback(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "old.db")
	dest := filepath.Join(dir, "new.db")
	back := filepath.Join(dir, "export.db")
	q, err := OpenSQLite(source, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		ev := richEvent(fmt.Sprint(i), uint64(i))
		ev.EventTime = uint64(i)
		if err = q.Enqueue(ev); err != nil {
			t.Fatal(err)
		}
	}
	q.MarkFailed("2", 2, "test failure")
	q.MarkPushed("3", 3)
	q.Close()
	before, _ := os.ReadFile(source)
	sum := sha256.Sum256(before)
	n, err := MigrateFrozen(context.Background(), source, dest, "v2")
	if err != nil || n != 3 {
		t.Fatalf("migration %d %v", n, err)
	}
	n, err = MigrateFrozen(context.Background(), source, dest, "v2")
	if err != nil || n != 0 {
		t.Fatalf("resume %d %v", n, err)
	}
	if _, err = MigrateFrozen(context.Background(), dest, back, "legacy"); err != nil {
		t.Fatal(err)
	}
	a, _ := readOnly(source)
	defer a.Close()
	b, _ := readOnly(back)
	defer b.Close()
	ar, err := readRecords(a, "SELECT "+recordColumns+" FROM event_queue ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	br, err := readRecords(b, "SELECT "+recordColumns+" FROM event_queue ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for i := range ar {
		if !jsonEqual([]byte(ar[i].Payload), []byte(br[i].Payload)) || ar[i].Status != br[i].Status || ar[i].Retry != br[i].Retry || ar[i].Error != br[i].Error {
			t.Fatal("migration changed data or delivery state")
		}
	}
	after, _ := os.ReadFile(source)
	if sha256.Sum256(after) != sum {
		t.Fatal("source mutated")
	}
}
func TestMixedLegacyAndV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	q, err := OpenSQLite(path, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	q.Enqueue(event.ThreatEvent{EventID: "old", EventTime: 1})
	q.Close()
	q, err = NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.Enqueue(event.ThreatEvent{EventID: "new", EventTime: 2})
	events, err := q.LoadPending(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("mixed read %v %v", events, err)
	}
}

func TestPacketRangeDoesNotReadUnrelatedChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.db")
	q, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	raw := append([]byte(strings.Repeat("a", 4096)), []byte(strings.Repeat("b", 4096))...)
	ev := event.ThreatEvent{EventID: "range", EventTime: 1, RawPacket: &event.RawPacketContext{PacketHex: hex.EncodeToString(raw), CaptureTruncated: true}}
	if err = q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	part, err := ReadPacketRange(path, "range", 4090, 20)
	if err != nil {
		t.Fatal(err)
	}
	if part.TotalLength != 8192 || !part.CaptureTruncated || part.PacketHex != hex.EncodeToString(raw[4090:4110]) {
		t.Fatalf("bad range %+v", part)
	}
	// Damage the second chunk: a first-chunk-only read still succeeds, while
	// full restoration and a range touching the corrupted chunk fail.
	canonical := append([]byte{0}, raw[4096:]...)
	hash := sha256.Sum256(canonical)
	q.db.Exec("UPDATE queue_content SET data=x'00' WHERE hash=?", hex.EncodeToString(hash[:]))
	if _, err = ReadPacketRange(path, "range", 0, 10); err != nil {
		t.Fatal("range loaded unrelated chunk", err)
	}
	if _, err = ReadPacketRange(path, "range", 4096, 10); err == nil {
		t.Fatal("corrupt range accepted")
	}
	if _, err = ReadEvent(path, "range"); err == nil {
		t.Fatal("corrupt full event accepted")
	}
}

func TestSummaryDoesNotRestorePacketContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.db")
	q, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ev := richEvent("summary", 1)
	ev.EventTime = 1
	if err = q.Enqueue(ev); err != nil {
		t.Fatal(err)
	}
	q.db.Exec("UPDATE queue_content SET data=x'00'")
	summaries, err := RecentPushSummaries(path, 10)
	if err != nil || len(summaries) != 1 {
		t.Fatalf("summary requires evidence %v", err)
	}
	if summaries[0].RawPacket == nil || summaries[0].RawPacket.PacketHex != "" {
		t.Fatal("summary expanded evidence")
	}
	if _, err = RecentPushLogs(path, 10); err == nil {
		t.Fatal("full legacy endpoint hid corruption")
	}
}

func TestArchiveRecoveryAndCancellation(t *testing.T) {
	dir := t.TempDir()
	q, err := NewSQLite(filepath.Join(dir, "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.Enqueue(event.ThreatEvent{EventID: "a", EventTime: 1})
	q.MarkPushed("a", 1)
	// Simulate a process dying after copying a segment, before source commit.
	orphan := filepath.Join(dir, "queue-"+uuid.NewString()+".db")
	if err = os.WriteFile(orphan, []byte("unfinished copy"), 0600); err != nil {
		t.Fatal(err)
	}
	q.db.Exec("INSERT INTO queue_archive_pending(path) VALUES(?)", orphan)
	if err = q.RecoverArchives(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("unfinished copy not reclaimed")
	}
	if _, err = q.LoadEvent(1); err != nil {
		t.Fatal("source lost during recovery")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = q.Archive(ctx, filepath.Join(dir, "archives"), time.Now().Add(time.Hour), 10); err == nil {
		t.Fatal("canceled archive succeeded")
	}
	if _, err = q.LoadEvent(1); err != nil {
		t.Fatal("canceled archive lost source")
	}
	if _, err = q.Archive(context.Background(), filepath.Join(dir, "archives"), time.Now().Add(time.Hour), 10); err != nil {
		t.Fatal(err)
	}
	paths, err := archivePaths(q.db)
	if err != nil || len(paths) != 1 {
		t.Fatal(paths, err)
	}
	// Crash after source commit, before intent cleanup: published segment survives.
	q.db.Exec("INSERT INTO queue_archive_pending(path) VALUES(?)", paths[0])
	if err = q.RecoverArchives(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(paths[0]); err != nil {
		t.Fatal("published segment removed")
	}
}

func TestArchiveAlongsideEnqueueAndQueries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q.db")
	q, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for i := 0; i < 8; i++ {
		ev := richEvent(fmt.Sprintf("old-%d", i), 1)
		ev.EventTime = 1
		if err = q.Enqueue(ev); err != nil {
			t.Fatal(err)
		}
		if err = q.MarkPushed(ev.EventID, 1); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	wg.Add(3)
	go func() {
		defer wg.Done()
		_, e := q.Archive(context.Background(), filepath.Join(dir, "archives"), time.Now().Add(time.Hour), 100)
		errs <- e
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			ev := richEvent(fmt.Sprintf("new-%d", i), 1)
			ev.EventTime = 1
			if e := q.Enqueue(ev); e != nil {
				errs <- e
				return
			}
		}
		errs <- nil
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			if _, e := RecentPushSummaries(path, 50); e != nil {
				errs <- e
				return
			}
		}
		errs <- nil
	}()
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, err = q.Collect(10000); err != nil {
		t.Fatal(err)
	}
	pending, err := q.LoadPending(100)
	if err != nil || len(pending) != 8 {
		t.Fatalf("pending %d %v", len(pending), err)
	}
	logs, err := RecentPushLogs(path, 50)
	if err != nil || len(logs) != 16 {
		t.Fatalf("history %d %v", len(logs), err)
	}
}

func TestInterruptedMigrationCannotBeActivated(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.db")
	dst := filepath.Join(dir, "target.db")
	q, err := OpenSQLite(src, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	q.Enqueue(event.ThreatEvent{EventID: "a", EventTime: 1})
	q.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = MigrateFrozen(ctx, src, dst, "v2"); err == nil {
		t.Fatal("canceled migration succeeded")
	}
	q, err = NewSQLite(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Activate(); err == nil {
		t.Fatal("incomplete migration activated")
	}
	q.Close()
	if _, err = MigrateFrozen(context.Background(), src, dst, "v2"); err != nil {
		t.Fatal(err)
	}
	q, err = NewSQLite(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Activate(); err != nil {
		t.Fatal(err)
	}
	q.Close()
	if _, err = MigrateFrozen(context.Background(), src, dst, "v2"); err == nil {
		t.Fatal("activated destination accepted stale import")
	}
}

func TestMigrationIncludesInterleavedArchives(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "export.db")
	q, err := NewSQLite(source)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		if err = q.Enqueue(event.ThreatEvent{EventID: fmt.Sprint(i), EventTime: uint64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, group := range [][]string{{"1", "5"}, {"2", "6"}} {
		for _, id := range group {
			if err = q.MarkPushed(id, 1); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = q.Archive(context.Background(), filepath.Join(dir, "archives"), time.Now().Add(time.Hour), 10); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := archivePaths(q.db)
	if err != nil {
		t.Fatal(err)
	}
	q.Close()
	if _, err = MigrateFrozen(context.Background(), source, paths[0], "legacy"); err == nil {
		t.Fatal("migration accepted a source archive as destination")
	}
	for _, expected := range []int64{6, 0} {
		if n, e := MigrateFrozen(context.Background(), source, destination, "legacy"); e != nil || n != expected {
			t.Fatalf("migration copied %d, want %d: %v", n, expected, e)
		}
	}
	db, err := readOnly(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := readRecords(db, "SELECT "+recordColumns+" FROM event_queue ORDER BY id")
	if err != nil || len(rows) != 6 {
		t.Fatalf("export count %d: %v", len(rows), err)
	}
	for i, row := range rows {
		if row.ID != int64(i+1) || row.Key != fmt.Sprint(i+1) {
			t.Fatalf("changed event identity: %+v", row)
		}
		pushed := row.ID != 3 && row.ID != 4
		if (row.Status == 2) != pushed {
			t.Fatalf("changed archived delivery state: %+v", row)
		}
	}
}

func TestMigrationPreservesEmptyQueueSequence(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "target.db")
	q, err := NewSQLite(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.db.Exec("INSERT INTO sqlite_sequence(name,seq) VALUES('event_queue',123)"); err != nil {
		t.Fatal(err)
	}
	q.Close()
	if _, err = MigrateFrozen(context.Background(), source, destination, "v2"); err != nil {
		t.Fatal(err)
	}
	q, err = NewSQLite(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err = q.Enqueue(event.ThreatEvent{EventID: "new", EventTime: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.LoadEvent(124); err != nil {
		t.Fatal("migration reused an old queue ID:", err)
	}
}
