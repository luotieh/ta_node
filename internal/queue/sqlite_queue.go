package queue

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"ta_node/internal/event"
)

type SQLiteQueue struct {
	db        *sql.DB
	path      string
	backend   string
	mu        sync.Mutex
	archiveMu sync.Mutex
	// maxRetry caps LoadPending to events with retry_count below it; events at
	// or over the cap stay in the table for inspection but are never retried.
	// 0 disables the cap.
	maxRetry int
}

// SetMaxRetry sets the retry cap applied by LoadPending. 0 means unlimited.
func (q *SQLiteQueue) SetMaxRetry(n int) { q.maxRetry = n }

func NewSQLite(path string) (*SQLiteQueue, error) { return OpenSQLite(path, "v2") }

func OpenSQLite(path, backend string) (*SQLiteQueue, error) {
	if backend == "" {
		backend = "v2"
	}
	if backend != "v2" && backend != "legacy" {
		return nil, fmt.Errorf("unknown storage backend %q", backend)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	q := &SQLiteQueue{db: db, path: path, backend: backend}
	if err := q.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return q, nil
}

func (q *SQLiteQueue) Close() error { return q.db.Close() }

// Activate rejects an interrupted migration and seals completed destinations
// against subsequently resuming a stale offline import over live data.
func (q *SQLiteQueue) Activate() error {
	var source string
	err := q.db.QueryRow("SELECT value FROM queue_metadata WHERE key='migration_source'").Scan(&source)
	if isMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var complete string
	if err = q.db.QueryRow("SELECT value FROM queue_metadata WHERE key='migration_complete'").Scan(&complete); err != nil || complete != "1" {
		return fmt.Errorf("queue migration is incomplete; resume ta_queue before starting the node")
	}
	_, err = q.db.Exec("INSERT OR REPLACE INTO queue_metadata(key,value) VALUES('migration_activated','1')")
	return err
}

func (q *SQLiteQueue) init() error {
	var existing int
	if err := q.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='event_queue'").Scan(&existing); err != nil {
		return err
	}
	_, err := q.db.Exec(`CREATE TABLE IF NOT EXISTS event_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  event_time INTEGER NOT NULL,
  payload TEXT NOT NULL,
  status INTEGER DEFAULT 0,
  retry_count INTEGER DEFAULT 0,
  last_error TEXT,
  created_at INTEGER,
  updated_at INTEGER
)`)
	if err != nil {
		return err
	}
	_, err = q.db.Exec(`
 PRAGMA busy_timeout=5000;
 PRAGMA journal_mode=WAL;
 CREATE TABLE IF NOT EXISTS queue_content(hash TEXT PRIMARY KEY,codec INTEGER NOT NULL,size INTEGER NOT NULL,data BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS queue_edges(parent TEXT NOT NULL,child TEXT NOT NULL,PRIMARY KEY(parent,child));
 CREATE INDEX IF NOT EXISTS queue_edges_child ON queue_edges(child);
 CREATE TABLE IF NOT EXISTS queue_summary(event_id TEXT PRIMARY KEY,payload TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS queue_roots(event_id TEXT PRIMARY KEY,hash TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS queue_roots_hash ON queue_roots(hash);
 CREATE TABLE IF NOT EXISTS queue_archived(event_id TEXT PRIMARY KEY,path TEXT NOT NULL,id INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS queue_archives(path TEXT PRIMARY KEY,min_id INTEGER NOT NULL,max_id INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS queue_archive_pending(path TEXT PRIMARY KEY);
 CREATE TABLE IF NOT EXISTS queue_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 INSERT OR IGNORE INTO queue_metadata VALUES('storage_schema','2');
 `)
	if err != nil {
		return err
	}
	// Never trigger a whole-table index build on a 500GB legacy DB at startup.
	// Offline migration creates these indexes on the empty destination instead.
	if existing == 0 {
		if _, err = q.db.Exec(`CREATE INDEX queue_pending ON event_queue(id) WHERE status IN (0,3); CREATE INDEX queue_pushed ON event_queue(updated_at,id) WHERE status=2;`); err != nil {
			return err
		}
	}
	var version string
	if err = q.db.QueryRow("SELECT value FROM queue_metadata WHERE key='storage_schema'").Scan(&version); err != nil {
		return err
	}
	if version != "2" {
		return fmt.Errorf("unsupported storage schema %s", version)
	}
	return nil
}

func isMissing(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func (q *SQLiteQueue) Enqueue(ev event.ThreatEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := queueRecordID(ev.EventID, ev.ContextRevision)
	// Compact routing index avoids opening every archive on every packet.
	var archived int
	lookupErr := q.db.QueryRow("SELECT 1 FROM queue_archived WHERE event_id=?", key).Scan(&archived)
	if lookupErr == nil {
		return nil
	}
	if !isMissing(lookupErr) {
		return lookupErr
	}
	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRow("SELECT 1 FROM event_queue WHERE event_id=?", key).Scan(&exists)
	if err == nil {
		return nil
	}
	if !isMissing(err) {
		return err
	}
	var payload string
	if q.backend == "legacy" {
		b, e := json.Marshal(ev)
		if e != nil {
			return e
		}
		payload = string(b)
	} else {
		payload, err = encodePayload(tx, ev)
		if err != nil {
			return err
		}
	}
	now := time.Now().Unix()
	if _, err = tx.Exec(`INSERT INTO event_queue(event_id,event_time,payload,status,created_at,updated_at) VALUES(?,?,?,?,?,?)`, key, ev.EventTime, payload, 0, now, now); err != nil {
		return err
	}
	if err = saveSummary(tx, key, ev); err != nil {
		return err
	}
	if err = registerRoot(tx, key, payload); err != nil {
		return err
	}
	return tx.Commit()
}

func registerRoot(tx *sql.Tx, key, payload string) error {
	root, err := payloadRoot(payload)
	if err != nil {
		return err
	}
	if root == "" {
		return nil
	}
	_, err = tx.Exec("INSERT OR REPLACE INTO queue_roots(event_id,hash) VALUES(?,?)", key, root)
	return err
}

type pendingEntry struct {
	id      int64
	created int64
}

func (q *SQLiteQueue) pendingEntries(limit int) ([]pendingEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.db.Query(`SELECT id,COALESCE(created_at,0) FROM event_queue WHERE status IN (0,3) AND (?<=0 OR retry_count<?) ORDER BY id LIMIT ?`, q.maxRetry, q.maxRetry, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pendingEntry
	for rows.Next() {
		var e pendingEntry
		if err = rows.Scan(&e.id, &e.created); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PendingIDs returns lightweight descriptors; only one complete event is restored
// at a time by the production push worker.
func (q *SQLiteQueue) PendingIDs(limit int) ([]int64, error) {
	entries, err := q.pendingEntries(limit)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(entries))
	for i, e := range entries {
		ids[i] = e.id
	}
	return ids, nil
}
func (q *SQLiteQueue) LoadEvent(id int64) (event.ThreatEvent, error) {
	var ev event.ThreatEvent
	var payload string
	tx, err := q.db.Begin()
	if err != nil {
		return ev, err
	}
	defer tx.Rollback()
	if err = tx.QueryRow("SELECT payload FROM event_queue WHERE id=?", id).Scan(&payload); err != nil {
		return ev, err
	}
	b, err := decodePayload(tx, payload)
	if err != nil {
		return ev, err
	}
	err = json.Unmarshal(b, &ev)
	return ev, err
}
func (q *SQLiteQueue) LoadPending(limit int) ([]event.ThreatEvent, error) {
	ids, err := q.PendingIDs(limit)
	if err != nil {
		return nil, err
	}
	var out []event.ThreatEvent
	for _, id := range ids {
		ev, err := q.LoadEvent(id)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (q *SQLiteQueue) MarkPushed(eventID string, contextRevision uint64) error {
	_, err := q.db.Exec(`UPDATE event_queue SET status=2, last_error='', updated_at=? WHERE event_id=?`, time.Now().Unix(), queueRecordID(eventID, contextRevision))
	return err
}

func (q *SQLiteQueue) MarkFailed(eventID string, contextRevision uint64, errMsg string) error {
	_, err := q.db.Exec(`UPDATE event_queue SET status=3, retry_count=retry_count+1, last_error=?, updated_at=? WHERE event_id=?`, errMsg, time.Now().Unix(), queueRecordID(eventID, contextRevision))
	return err
}

// queueRecordID keeps the legacy event_id UNIQUE schema usable while allowing
// multiple immutable context revisions. The payload always retains the real
// event_id; only the queue's internal dedupe key receives the revision suffix.
func queueRecordID(eventID string, contextRevision uint64) string {
	if contextRevision <= 1 {
		return eventID
	}
	return eventID + "@revision:" + strconv.FormatUint(contextRevision, 10)
}
