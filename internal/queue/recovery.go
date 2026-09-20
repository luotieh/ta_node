package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// RecoverArchives is used only by the sole node writer under q.mu. A pending
// entry is committed before any segment is written. Catalog publication and
// source deletion are one transaction: no catalog means the source is intact.
func (q *SQLiteQueue) RecoverArchives() error {
	q.archiveMu.Lock()
	defer q.archiveMu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.recoverArchivesLocked()
}
func (q *SQLiteQueue) recoverArchivesLocked() error {
	rows, err := q.db.Query("SELECT path FROM queue_archive_pending")
	if err != nil {
		return err
	}
	var paths []string
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range paths {
		name := filepath.Base(p)
		id := strings.TrimSuffix(strings.TrimPrefix(name, "queue-"), ".db")
		if _, err = uuid.Parse(id); err != nil || name != "queue-"+id+".db" || !filepath.IsAbs(p) {
			return fmt.Errorf("invalid archive recovery path %q", p)
		}
		var published int
		err = q.db.QueryRow("SELECT 1 FROM queue_archives WHERE path=?", p).Scan(&published)
		if err == nil {
			if _, err = os.Stat(p); err != nil {
				return fmt.Errorf("published archive missing: %w", err)
			}
		} else if isMissing(err) {
			// These files belong to this incomplete copy; no source events were removed.
			for _, suffix := range []string{"", "-journal"} {
				if err = os.Remove(p + suffix); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		} else {
			return err
		}
		if _, err = q.db.Exec("DELETE FROM queue_archive_pending WHERE path=?", p); err != nil {
			return err
		}
	}
	return nil
}
