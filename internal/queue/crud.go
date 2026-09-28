package queue

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PushLogQuery filters and pages the queue-backed push log listing.
type PushLogQuery struct {
	Offset int
	Limit  int
	Status string // "", "pending", "pushed", "failed"
	Search string // substring match on event ID or summary payload (IOC/IP/...)
}

// fetchBuffer multiplies the page window because each event may have several
// context revisions that collapse into one row after dedupe.
const fetchBuffer = 4
const maxFetch = 20000

// ListPushLogs returns one row per event (latest context revision), filtered
// and paged across every shard database and archive segment. The boolean
// reports whether more rows may follow the returned page.
func ListPushLogs(path string, query PushLogQuery) ([]PushLog, bool, error) {
	if query.Limit <= 0 || query.Limit > 200 {
		query.Limit = 50
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	if _, err := os.Stat(path); err != nil {
		return nil, false, err
	}
	status := ""
	switch query.Status {
	case "":
	case "pending":
		status = "0"
	case "pushed":
		status = "2"
	case "failed":
		status = "3"
	default:
		return nil, false, fmt.Errorf("unknown status %q", query.Status)
	}
	search := strings.TrimSpace(query.Search)
	fetch := (query.Offset + query.Limit) * fetchBuffer
	if fetch > maxFetch {
		fetch = maxFetch
	}
	var records []record
	capped := false
	for _, p := range shardPaths(path) {
		recs, hit, err := queryShardRecords(p, status, search, fetch)
		if err != nil {
			return nil, false, err
		}
		records = append(records, recs...)
		capped = capped || hit
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Updated != records[j].Updated {
			return records[i].Updated > records[j].Updated
		}
		if records[i].Created != records[j].Created {
			return records[i].Created > records[j].Created
		}
		return records[i].ID > records[j].ID
	})
	var logs []PushLog
	seen := map[string]bool{}
	for _, rec := range records {
		log, key, decoded := pushLogFromRecord(rec, true)
		if decoded {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		logs = append(logs, log)
	}
	hasMore := capped || len(logs) > query.Offset+query.Limit
	if query.Offset >= len(logs) {
		return []PushLog{}, hasMore, nil
	}
	end := query.Offset + query.Limit
	if end > len(logs) {
		end = len(logs)
	}
	return logs[query.Offset:end], hasMore, nil
}

// queryShardRecords reads one shard database plus its archive segments.
func queryShardRecords(path, status, search string, fetch int) ([]record, bool, error) {
	db, err := readOnly(path)
	if err != nil {
		return nil, false, err
	}
	defer db.Close()
	out, archives, err := queryDBRecords(db, status, search, fetch)
	if err != nil {
		return nil, false, err
	}
	capped := len(out) == fetch
	for _, archive := range archives {
		adb, err := readOnly(archive)
		if err != nil {
			return nil, false, fmt.Errorf("open archive: %w", err)
		}
		part, _, err := queryDBRecords(adb, status, search, fetch)
		adb.Close()
		if err != nil {
			return nil, false, err
		}
		out = append(out, part...)
		if len(part) == fetch {
			capped = true
		}
	}
	return out, capped, nil
}

// queryDBRecords selects matching rows inside one read transaction so content
// references stay consistent while payloads are decoded. It also returns the
// archive segment catalog recorded in the database.
func queryDBRecords(db *sql.DB, status, search string, fetch int) ([]record, []string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	columns, err := summaryColumns(tx, true)
	if err != nil {
		return nil, nil, err
	}
	var archives []string
	var exists int
	if err = tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_archives'").Scan(&exists); err != nil {
		return nil, nil, err
	}
	if exists > 0 {
		rows, e := tx.Query("SELECT path FROM queue_archives")
		if e != nil {
			return nil, nil, e
		}
		for rows.Next() {
			var p string
			if e = rows.Scan(&p); e != nil {
				rows.Close()
				return nil, nil, e
			}
			archives = append(archives, p)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, nil, err
		}
		rows.Close()
	}
	payloadExpr := "payload"
	if columns != recordColumns {
		payloadExpr = summaryPayloadExpr
	}
	where := "1=1"
	var args []any
	if status != "" {
		where += " AND status=" + status
	}
	if search != "" {
		like := "%" + likeEscaper.Replace(search) + "%"
		where += " AND (event_id LIKE ? ESCAPE '\\' OR " + payloadExpr + " LIKE ? ESCAPE '\\')"
		args = append(args, like, like)
	}
	args = append(args, fetch)
	rows, err := tx.Query("SELECT "+columns+" FROM event_queue WHERE "+where+" ORDER BY updated_at DESC, id DESC LIMIT ?", args...)
	if err != nil {
		return nil, nil, err
	}
	var out []record
	for rows.Next() {
		r, e := scanRecord(rows)
		if e != nil {
			rows.Close()
			return nil, nil, e
		}
		out = append(out, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	for i := range out {
		b, e := decodePayload(tx, out[i].Payload)
		if e != nil {
			return nil, nil, e
		}
		out[i].Payload = string(b)
	}
	return out, archives, nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
var globEscaper = strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]")

// revisionPattern matches the base event row plus every context revision row.
func revisionPattern(eventID string) string {
	return globEscaper.Replace(eventID) + "@revision:*"
}

// mutableDB opens an existing database read-write with the same busy timeout
// the live queue connections use, so admin writes queue behind node traffic.
func mutableDB(path string) (*sql.DB, error) {
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
	u := url.URL{Scheme: "file", Path: p, RawQuery: "mode=rw"}
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

func validEventID(eventID string) error {
	if eventID == "" || len(eventID) > 512 {
		return fmt.Errorf("invalid event id")
	}
	return nil
}

// RequeueEvent resets every revision of the event in the active shard
// databases to pending with a fresh retry budget, so the push worker sends
// them again. Archived segments are acknowledged history and stay untouched.
func RequeueEvent(path, eventID string) (int64, error) {
	if err := validEventID(eventID); err != nil {
		return 0, err
	}
	if _, err := os.Stat(path); err != nil {
		return 0, err
	}
	pattern := revisionPattern(eventID)
	now := time.Now().Unix()
	var total int64
	for _, p := range shardPaths(path) {
		db, err := mutableDB(p)
		if err != nil {
			return total, err
		}
		res, err := db.Exec(`UPDATE event_queue SET status=0, retry_count=0, last_error='', updated_at=? WHERE event_id=? OR event_id GLOB ?`, now, eventID, pattern)
		db.Close()
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	if total == 0 {
		return 0, sql.ErrNoRows
	}
	return total, nil
}

// DeleteEvent removes every revision of the event from the active shard
// databases, mirroring the archive path's cleanup (summary and content roots
// are dropped; unreferenced content is reclaimed by Collect). Archived
// segments are left untouched.
func DeleteEvent(path, eventID string) (int64, error) {
	if err := validEventID(eventID); err != nil {
		return 0, err
	}
	if _, err := os.Stat(path); err != nil {
		return 0, err
	}
	pattern := revisionPattern(eventID)
	var total int64
	for _, p := range shardPaths(path) {
		db, err := mutableDB(p)
		if err != nil {
			return total, err
		}
		n, err := deleteEventFrom(db, eventID, pattern)
		db.Close()
		if err != nil {
			return total, err
		}
		total += n
	}
	if total == 0 {
		return 0, sql.ErrNoRows
	}
	return total, nil
}

func deleteEventFrom(db *sql.DB, eventID, pattern string) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, table := range []string{"queue_summary", "queue_roots"} {
		if _, err = tx.Exec("DELETE FROM "+table+" WHERE event_id=? OR event_id GLOB ?", eventID, pattern); err != nil {
			return 0, err
		}
	}
	res, err := tx.Exec("DELETE FROM event_queue WHERE event_id=? OR event_id GLOB ?", eventID, pattern)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}
