package queue

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"

	"ta_node/internal/event"
)

type SQLiteQueue struct {
	db *sql.DB
	// maxRetry caps LoadPending to events with retry_count below it; events at
	// or over the cap stay in the table for inspection but are never retried.
	// 0 disables the cap.
	maxRetry int
}

// SetMaxRetry sets the retry cap applied by LoadPending. 0 means unlimited.
func (q *SQLiteQueue) SetMaxRetry(n int) { q.maxRetry = n }

func NewSQLite(path string) (*SQLiteQueue, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	q := &SQLiteQueue{db: db}
	if err := q.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return q, nil
}

func (q *SQLiteQueue) Close() error { return q.db.Close() }

func (q *SQLiteQueue) init() error {
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
	return err
}

func (q *SQLiteQueue) Enqueue(ev event.ThreatEvent) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = q.db.Exec(`INSERT OR IGNORE INTO event_queue(event_id,event_time,payload,status,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		queueRecordID(ev.EventID, ev.ContextRevision), ev.EventTime, string(payload), 0, now, now)
	return err
}

func (q *SQLiteQueue) LoadPending(limit int) ([]event.ThreatEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.db.Query(`SELECT payload FROM event_queue WHERE status IN (0,3) AND (? <= 0 OR retry_count < ?) ORDER BY id LIMIT ?`, q.maxRetry, q.maxRetry, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.ThreatEvent
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var ev event.ThreatEvent
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
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
