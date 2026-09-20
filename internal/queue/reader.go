package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"ta_node/internal/event"
)

// readRecords holds a consistent read transaction until content is restored.
// This prevents archive GC from deleting content underneath a reader.
func readRecords(db *sql.DB, query string, args ...any) ([]record, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var out []record
	for rows.Next() {
		r, e := scanRecord(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		b, e := decodePayload(tx, out[i].Payload)
		if e != nil {
			return nil, e
		}
		out[i].Payload = string(b)
	}
	return out, nil
}
func recentRecords(path string, limit int, summary bool) ([]record, error) {
	db, err := readOnly(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// Catalog and active rows must share a snapshot across archive publication.
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_archives'").Scan(&exists); err != nil {
		return nil, err
	}
	type location struct {
		path  string
		maxID int64
	}
	var paths []location
	if exists > 0 {
		rows, e := tx.Query("SELECT path,max_id FROM queue_archives ORDER BY max_id DESC")
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var p location
			if e = rows.Scan(&p.path, &p.maxID); e != nil {
				rows.Close()
				return nil, e
			}
			paths = append(paths, p)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	columns, err := summaryColumns(tx, summary)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query("SELECT "+columns+" FROM event_queue ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	var out []record
	for rows.Next() {
		r, e := scanRecord(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		b, e := decodePayload(tx, out[i].Payload)
		if e != nil {
			return nil, e
		}
		out[i].Payload = string(b)
	}
	for _, p := range paths {
		if len(out) >= limit && p.maxID < out[len(out)-1].ID {
			break
		}
		archive, e := readOnly(p.path)
		if e != nil {
			return nil, fmt.Errorf("open archive: %w", e)
		}
		at, e := archive.Begin()
		if e != nil {
			archive.Close()
			return nil, e
		}
		cols, e := summaryColumns(at, summary)
		at.Rollback()
		if e != nil {
			archive.Close()
			return nil, e
		}
		part, e := readRecords(archive, "SELECT "+cols+" FROM event_queue ORDER BY id DESC LIMIT ?", limit)
		archive.Close()
		if e != nil {
			return nil, e
		}
		out = append(out, part...)
		sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
		if len(out) > limit {
			out = out[:limit]
		}
	}
	return out, nil
}

// ReadEvent resolves active or archived records without creating a database.
func ReadEvent(path, key string) (event.ThreatEvent, error) {
	var ev event.ThreatEvent
	db, err := readOnly(path)
	if err != nil {
		return ev, err
	}
	defer db.Close()
	// Read active first; archive publication only moves records out, never back.
	// Reading the catalog afterwards covers a concurrent move.
	records, err := readRecords(db, "SELECT "+recordColumns+" FROM event_queue WHERE event_id=?", key)
	if err != nil {
		return ev, err
	}
	if len(records) == 0 {
		var exists int
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_archived'").Scan(&exists); err != nil {
			return ev, err
		}
		var paths []string
		var e error
		if exists > 0 {
			var p string
			e = db.QueryRow("SELECT path FROM queue_archived WHERE event_id=?", key).Scan(&p)
			if e == nil {
				paths = []string{p}
			} else if !isMissing(e) {
				return ev, e
			}
		} else {
			paths, e = archivePaths(db)
		}
		if e != nil && !isMissing(e) {
			return ev, e
		}
		for _, p := range paths {
			archive, e := readOnly(p)
			if e != nil {
				return ev, e
			}
			records, e = readRecords(archive, "SELECT "+recordColumns+" FROM event_queue WHERE event_id=?", key)
			archive.Close()
			if e != nil {
				return ev, e
			}
			if len(records) > 0 {
				break
			}
		}
	}
	if len(records) == 0 {
		return ev, sql.ErrNoRows
	}
	err = json.Unmarshal([]byte(records[0].Payload), &ev)
	return ev, err
}
