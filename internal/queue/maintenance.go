package queue

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"ta_node/internal/event"
)

type record struct {
	ID               int64
	Key              string
	Time             uint64
	Payload          string
	Status, Retry    int
	Error            string
	Created, Updated int64
}

const recordColumns = "id,event_id,event_time,payload,status,retry_count,COALESCE(last_error,''),COALESCE(created_at,0),COALESCE(updated_at,0)"

func scanRecord(row interface{ Scan(...any) error }) (record, error) {
	var r record
	err := row.Scan(&r.ID, &r.Key, &r.Time, &r.Payload, &r.Status, &r.Retry, &r.Error, &r.Created, &r.Updated)
	return r, err
}
func insertRecord(tx *sql.Tx, r record) error {
	_, err := tx.Exec(`INSERT INTO event_queue(id,event_id,event_time,payload,status,retry_count,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, r.ID, r.Key, r.Time, r.Payload, r.Status, r.Retry, r.Error, r.Created, r.Updated)
	if err != nil {
		return err
	}
	b, err := decodePayload(tx, r.Payload)
	if err != nil {
		return err
	}
	var ev event.ThreatEvent
	if err = json.Unmarshal(b, &ev); err != nil {
		return err
	}
	if err = saveSummary(tx, r.Key, ev); err != nil {
		return err
	}
	return registerRoot(tx, r.Key, r.Payload)
}
func readOnly(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(abs); err != nil {
		return nil, err
	}
	p := filepath.ToSlash(abs)
	if len(p) > 1 && p[1] == ':' {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err == nil {
		db.SetMaxOpenConns(1)
		if _, e := db.Exec("PRAGMA busy_timeout=5000"); e != nil {
			db.Close()
			return nil, e
		}
	}
	return db, err
}
func archivePaths(db *sql.DB) ([]string, error) {
	var exists int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_archives'").Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, nil
	}
	rows, err := db.Query("SELECT path FROM queue_archives ORDER BY max_id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func copyPayload(src sqlReader, dst *sql.Tx, payload string) (string, error) {
	root, err := payloadRoot(payload)
	if err != nil {
		return "", err
	}
	if root == "" {
		var value any
		dec := json.NewDecoder(bytes.NewBufferString(payload))
		dec.UseNumber()
		if err = dec.Decode(&value); err != nil {
			return "", err
		}
		return encodePayload(dst, value)
	}
	w := objectWriter{tx: dst, known: map[string][]byte{}}
	visiting := map[string]bool{}
	done := map[string]bool{}
	var visit func(string, int) error
	visit = func(id string, depth int) error {
		if done[id] {
			return nil
		}
		if depth > 256 || visiting[id] {
			return fmt.Errorf("invalid content graph")
		}
		visiting[id] = true
		defer delete(visiting, id)
		raw, err := readObject(src, id)
		if err != nil {
			return err
		}
		var n contentNode
		if err = decodeNode(raw, &n); err != nil {
			return err
		}
		for _, child := range nodeRefs(n) {
			if err = visit(child, depth+1); err != nil {
				return err
			}
		}
		f, err := w.save(n)
		if err != nil {
			return err
		}
		if f.Ref != id {
			return fmt.Errorf("noncanonical content %s", id)
		}
		done[id] = true
		return nil
	}
	if err = visit(root, 0); err != nil {
		return "", err
	}
	return payload, nil
}

// Archive moves a bounded batch of acknowledged events into a self-contained,
// verified segment. A crash before catalog publication only leaves an orphan
// segment; source rows remain. Never removes pending or failed events.
func (q *SQLiteQueue) Archive(ctx context.Context, dir string, before time.Time, limit int) (int, error) {
	if dir == "" {
		return 0, fmt.Errorf("archive directory required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q.archiveMu.Lock()
	defer q.archiveMu.Unlock()
	dir, err := filepath.Abs(dir)
	if err != nil {
		return 0, err
	}
	if err = os.MkdirAll(dir, 0750); err != nil {
		return 0, err
	}
	if err = q.recoverArchivesLocked(); err != nil {
		return 0, err
	}
	path := filepath.Join(dir, "queue-"+uuid.NewString()+".db")
	if _, err = q.db.Exec("INSERT INTO queue_archive_pending(path) VALUES(?)", path); err != nil {
		return 0, err
	}
	// Registered before the source transaction, so its rollback runs first.
	defer func() { _ = q.recoverArchivesLocked() }()
	rows, err := q.db.QueryContext(ctx, `SELECT `+strings.Replace(recordColumns, "payload", "''", 1)+` FROM event_queue WHERE status=2 AND updated_at<? ORDER BY id LIMIT ?`, before.Unix(), limit)
	if err != nil {
		return 0, err
	}
	var records []record
	for rows.Next() {
		r, e := scanRecord(rows)
		if e != nil {
			rows.Close()
			return 0, e
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(records) == 0 {
		return 0, err
	}
	segment, err := OpenSQLite(path, "v2")
	if err != nil {
		return 0, err
	}
	defer segment.Close()
	dest, err := segment.db.Begin()
	if err != nil {
		return 0, err
	}
	defer dest.Rollback()
	for _, r := range records {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		if err = q.db.QueryRow("SELECT payload FROM event_queue WHERE id=?", r.ID).Scan(&r.Payload); err != nil {
			return 0, err
		}
		payload, e := copyPayload(q.db, dest, r.Payload)
		if e != nil {
			return 0, e
		}
		r.Payload = payload
		if err = insertRecord(dest, r); err != nil {
			return 0, err
		}
	}
	if err = dest.Commit(); err != nil {
		return 0, err
	}
	if err = segment.Close(); err != nil {
		return 0, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if err = syncDirectory(dir); err != nil {
		return 0, err
	}
	// Verify the published file itself, not just the write connection.
	verify, err := readOnly(path)
	if err != nil {
		return 0, err
	}
	defer verify.Close()
	for _, r := range records {
		saved, e := scanRecord(verify.QueryRow("SELECT "+recordColumns+" FROM event_queue WHERE id=?", r.ID))
		if e != nil {
			return 0, e
		}
		if err = q.db.QueryRow("SELECT payload FROM event_queue WHERE id=?", r.ID).Scan(&r.Payload); err != nil {
			return 0, err
		}
		original, e := decodePayload(q.db, r.Payload)
		if e != nil {
			return 0, e
		}
		restored, e := decodePayload(verify, saved.Payload)
		if e != nil {
			return 0, e
		}
		if !jsonEqual(original, restored) || saved.Key != r.Key || saved.Time != r.Time || saved.Status != r.Status || saved.Retry != r.Retry || saved.Error != r.Error || saved.Created != r.Created || saved.Updated != r.Updated {
			return 0, fmt.Errorf("archive verification failed for %d", r.ID)
		}
	}
	// Copy and verification used only short read statements. The sole archiver
	// excludes GC; immutable roots remain live until this short publication tx.
	q.mu.Lock()
	defer q.mu.Unlock()
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, r := range records {
		current, e := scanRecord(tx.QueryRow("SELECT "+recordColumns+" FROM event_queue WHERE id=?", r.ID))
		if e != nil {
			return 0, e
		}
		if current.Key != r.Key || current.Status != r.Status || current.Retry != r.Retry || current.Updated != r.Updated || current.Created != r.Created || current.Error != r.Error {
			return 0, fmt.Errorf("source record changed during archive: %d", r.ID)
		}
	}
	if _, err = tx.Exec("INSERT INTO queue_archives(path,min_id,max_id) VALUES(?,?,?)", path, records[0].ID, records[len(records)-1].ID); err != nil {
		return 0, err
	}
	for _, r := range records {
		if _, err = tx.Exec("INSERT INTO queue_archived(event_id,path,id) VALUES(?,?,?)", r.Key, path, r.ID); err != nil {
			return 0, err
		}
		if _, err = tx.Exec("DELETE FROM queue_summary WHERE event_id=?", r.Key); err != nil {
			return 0, err
		}
		if _, err = tx.Exec("DELETE FROM queue_roots WHERE event_id=?", r.Key); err != nil {
			return 0, err
		}
		if _, err = tx.Exec("DELETE FROM event_queue WHERE id=? AND status=2", r.ID); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(records), nil
}
func jsonEqual(a, b []byte) bool {
	decode := func(raw []byte) (any, error) {
		var v any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		e := d.Decode(&v)
		return v, e
	}
	av, ae := decode(a)
	bv, be := decode(b)
	if ae != nil || be != nil {
		return false
	}
	aa, _ := json.Marshal(av)
	bb, _ := json.Marshal(bv)
	return bytes.Equal(aa, bb)
}

// Collect removes only graph nodes with neither event roots nor parent refs.
// Bounded work and a transaction prevent deletion of shared/live evidence.
func (q *SQLiteQueue) Collect(limit int) (int, error) {
	if limit <= 0 {
		limit = 1000
	}
	q.archiveMu.Lock()
	defer q.archiveMu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	tx, err := q.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	removed := 0
	for removed < limit {
		rows, err := tx.Query(`SELECT hash FROM queue_content c WHERE NOT EXISTS(SELECT 1 FROM queue_roots WHERE hash=c.hash) AND NOT EXISTS(SELECT 1 FROM queue_edges WHERE child=c.hash) LIMIT ?`, limit-removed)
		if err != nil {
			return 0, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return 0, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return 0, err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if _, err = tx.Exec("DELETE FROM queue_edges WHERE parent=?", id); err != nil {
				return 0, err
			}
			if _, err = tx.Exec("DELETE FROM queue_content WHERE hash=?", id); err != nil {
				return 0, err
			}
			removed++
		}
	}
	return removed, tx.Commit()
}

type StorageStats struct {
	PageBytes       int64  `json:"page_bytes"`
	ReusableBytes   int64  `json:"reusable_bytes"`
	FileBytes       int64  `json:"file_bytes"`
	AvailableBytes  uint64 `json:"available_bytes"`
	ArchiveSegments int    `json:"archive_segments"`
	Backend         string `json:"backend"`
}

func (q *SQLiteQueue) Stats() (StorageStats, error) {
	s := StorageStats{Backend: q.backend}
	var size, pages, free int64
	for _, v := range []struct {
		name string
		dst  *int64
	}{{"page_size", &size}, {"page_count", &pages}, {"freelist_count", &free}} {
		if err := q.db.QueryRow("PRAGMA " + v.name).Scan(v.dst); err != nil {
			return s, err
		}
	}
	s.PageBytes = size * pages
	s.ReusableBytes = size * free
	for _, suffix := range []string{"", "-wal", "-journal"} {
		if f, e := os.Stat(q.path + suffix); e == nil {
			s.FileBytes += f.Size()
		}
	}
	var hasCatalog int
	if err := q.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_archives'").Scan(&hasCatalog); err != nil {
		return s, err
	}
	if hasCatalog > 0 {
		if err := q.db.QueryRow("SELECT count(*) FROM queue_archives").Scan(&s.ArchiveSegments); err != nil {
			return s, err
		}
	}
	var err error
	s.AvailableBytes, err = availableBytes(filepath.Dir(q.path))
	return s, err
}

// InspectStorage does not initialize, migrate or write to the selected file.
func InspectStorage(path string) (StorageStats, error) {
	db, err := readOnly(path)
	if err != nil {
		return StorageStats{}, err
	}
	defer db.Close()
	var v2 int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_content'").Scan(&v2); err != nil {
		return StorageStats{}, err
	}
	backend := "legacy"
	if v2 > 0 {
		backend = "v2/mixed"
	}
	return (&SQLiteQueue{db: db, path: path, backend: backend}).Stats()
}
