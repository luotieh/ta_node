package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// MigrateFrozen copies an offline, checkpointed source and its immutable archive
// segments into a separate destination. It never modifies the source. Every row
// is verified before the cursor and row commit together. Resume is restricted to
// the exact same frozen source files; live migration is deliberately rejected.
func MigrateFrozen(ctx context.Context, source, destination, backend string) (int64, error) {
	source, err := filepath.Abs(source)
	if err != nil {
		return 0, err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return 0, err
	}
	srcInfo, err := os.Stat(source)
	if err != nil {
		return 0, err
	}
	if dstInfo, e := os.Stat(destination); e == nil && os.SameFile(srcInfo, dstInfo) {
		return 0, fmt.Errorf("source and destination are the same file")
	}
	src, err := readOnly(source)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	archives, err := archivePaths(src)
	if err != nil {
		return 0, err
	}
	paths := append([]string{source}, archives...)
	type identity struct {
		Path           string
		Size, Modified int64
	}
	var identities []identity
	for _, p := range paths {
		info, e := os.Stat(p)
		if e != nil {
			return 0, e
		}
		if dstInfo, e := os.Stat(destination); e == nil && os.SameFile(info, dstInfo) {
			return 0, fmt.Errorf("destination is a source archive file")
		}
		if wi, e := os.Stat(p + "-wal"); e == nil && wi.Size() > 0 {
			return 0, fmt.Errorf("source %s has WAL; use a consistent offline checkpointed backup", p)
		}
		identities = append(identities, identity{p, info.Size(), info.ModTime().UnixNano()})
	}
	fingerprint, _ := json.Marshal(identities)
	dst, err := OpenSQLite(destination, backend)
	if err != nil {
		return 0, err
	}
	defer dst.Close()
	var activated string
	err = dst.db.QueryRow("SELECT value FROM queue_metadata WHERE key='migration_activated'").Scan(&activated)
	if err == nil {
		return 0, fmt.Errorf("destination was activated by a node; refuse stale migration resume")
	}
	if !isMissing(err) {
		return 0, err
	}
	var saved string
	err = dst.db.QueryRow("SELECT value FROM queue_metadata WHERE key='migration_source'").Scan(&saved)
	if isMissing(err) {
		var count int
		if err = dst.db.QueryRow("SELECT count(*) FROM event_queue").Scan(&count); err != nil {
			return 0, err
		}
		if count != 0 {
			return 0, fmt.Errorf("destination contains events without a migration cursor")
		}
		tx, e := dst.db.Begin()
		if e != nil {
			return 0, e
		}
		defer tx.Rollback()
		if _, e = tx.Exec("INSERT INTO queue_metadata(key,value) VALUES('migration_source',?),('migration_backend',?),('migration_cursor','0')", string(fingerprint), backend); e != nil {
			return 0, e
		}
		if e = tx.Commit(); e != nil {
			return 0, e
		}
	} else if err != nil {
		return 0, err
	} else if saved != string(fingerprint) {
		return 0, fmt.Errorf("frozen source identity changed; refuse unsafe resume")
	}
	var storedBackend string
	if err = dst.db.QueryRow("SELECT value FROM queue_metadata WHERE key='migration_backend'").Scan(&storedBackend); err != nil {
		return 0, err
	}
	if storedBackend != backend {
		return 0, fmt.Errorf("migration backend changed")
	}
	if err = dst.db.QueryRow("SELECT value FROM queue_metadata WHERE key='migration_cursor'").Scan(&saved); err != nil {
		return 0, err
	}
	cursor, err := strconv.ParseInt(saved, 10, 64)
	if err != nil {
		return 0, err
	}
	var copied int64
	// Scan one immutable file at a time. IDs are inserted explicitly, so file
	// order cannot change delivery order. Per-file cursors bound open handles and
	// avoid querying every archive for every event. The old global cursor is a
	// resume floor for destinations made by earlier versions of this tool.
	for index, path := range paths {
		cursorKey := "migration_file_" + strconv.Itoa(index)
		fileCursor := cursor
		err = dst.db.QueryRow("SELECT value FROM queue_metadata WHERE key=?", cursorKey).Scan(&saved)
		if err == nil {
			if saved == "complete" {
				continue
			}
			fileCursor, err = strconv.ParseInt(saved, 10, 64)
		} else if isMissing(err) {
			err = nil
		}
		if err != nil {
			return copied, err
		}
		origin, e := readOnly(path)
		if e != nil {
			return copied, e
		}
		err = func() error {
			defer origin.Close()
			for {
				if err = ctx.Err(); err != nil {
					return err
				}
				selected, e := scanRecord(origin.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM event_queue WHERE id>? ORDER BY id LIMIT 1", fileCursor))
				if isMissing(e) {
					_, e = dst.db.Exec("INSERT OR REPLACE INTO queue_metadata(key,value) VALUES(?, 'complete')", cursorKey)
					return e
				}
				if e != nil {
					return e
				}
				tx, e := dst.db.Begin()
				if e != nil {
					return e
				}
				e = func() error {
					original, e := decodePayload(origin, selected.Payload)
					if e != nil {
						return e
					}
					if backend == "legacy" {
						selected.Payload = string(original)
					} else {
						selected.Payload, e = copyPayload(origin, tx, selected.Payload)
						if e != nil {
							return e
						}
					}
					restored, e := decodePayload(tx, selected.Payload)
					if e != nil {
						return e
					}
					if !jsonEqual(original, restored) {
						return fmt.Errorf("migration payload mismatch at %d", selected.ID)
					}
					if e = insertRecord(tx, selected); e != nil {
						return e
					}
					_, e = tx.Exec("INSERT OR REPLACE INTO queue_metadata(key,value) VALUES(?,?)", cursorKey, strconv.FormatInt(selected.ID, 10))
					return e
				}()
				if e != nil {
					tx.Rollback()
					return e
				}
				if e = tx.Commit(); e != nil {
					return e
				}
				fileCursor = selected.ID
				copied++
			}
		}()
		if err != nil {
			return copied, err
		}
	}
	for _, id := range identities {
		f, e := os.Stat(id.Path)
		if e != nil {
			return copied, e
		}
		if f.Size() != id.Size || f.ModTime().UnixNano() != id.Modified {
			return copied, fmt.Errorf("source changed during migration; do not activate destination")
		}
	}
	// Preserve allocator high water even if the source archived/deleted its tail.
	var sequence int64
	err = src.QueryRow("SELECT seq FROM sqlite_sequence WHERE name='event_queue'").Scan(&sequence)
	if err != nil && !isMissing(err) {
		return copied, err
	}
	if sequence > cursor {
		if _, err = dst.db.Exec("UPDATE sqlite_sequence SET seq=max(seq,?) WHERE name='event_queue'", sequence); err != nil {
			return copied, err
		}
		if _, err = dst.db.Exec("INSERT INTO sqlite_sequence(name,seq) SELECT 'event_queue',? WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='event_queue')", sequence); err != nil {
			return copied, err
		}
	}
	_, err = dst.db.Exec("INSERT OR REPLACE INTO queue_metadata(key,value) VALUES('migration_complete','1')")
	return copied, err
}
