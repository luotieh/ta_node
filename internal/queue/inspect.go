package queue

import (
	"database/sql"
	"encoding/json"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"ta_node/internal/event"
)

type PushLog struct {
	EventID   string `json:"event_id"`
	EventTime uint64 `json:"event_time"`
	// OccurredAt is when the traffic that raised the event was captured (unix
	// seconds, from the microsecond event_time; falls back to created_at).
	// UpdatedAt only tracks the last push attempt — a retrying backlog event
	// always looks current by UpdatedAt, so display OccurredAt for "when".
	OccurredAt int64  `json:"occurred_at"`
	CreatedAt  int64  `json:"created_at"`
	EventName  string `json:"event_name"`
	Severity   string `json:"severity"`
	IOCType    string `json:"ioc_type,omitempty"`
	IOCValue   string `json:"ioc_value,omitempty"`
	SrcIP      string `json:"src_ip,omitempty"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
	Status     string `json:"status"`
	RetryCount int    `json:"retry_count"`
	LastError  string `json:"last_error,omitempty"`
	UpdatedAt  int64  `json:"updated_at"`
}

func RecentPushLogs(path string, limit int) ([]PushLog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT event_id,event_time,payload,status,retry_count,COALESCE(last_error,''),COALESCE(created_at,0),updated_at FROM event_queue ORDER BY updated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []PushLog
	for rows.Next() {
		var payload string
		var status int
		log := PushLog{}
		if err := rows.Scan(&log.EventID, &log.EventTime, &payload, &status, &log.RetryCount, &log.LastError, &log.CreatedAt, &log.UpdatedAt); err != nil {
			return nil, err
		}
		var ev event.ThreatEvent
		if err := json.Unmarshal([]byte(payload), &ev); err == nil {
			log.EventName = ev.EventName
			log.Severity = ev.Severity
			log.IOCType = ev.IOCType
			log.IOCValue = ev.IOCValue
			log.SrcIP = ev.SrcIP
			log.SrcPort = ev.SrcPort
			log.DstIP = ev.DstIP
			log.DstPort = ev.DstPort
		}
		log.OccurredAt = int64(log.EventTime / 1_000_000)
		if log.OccurredAt == 0 {
			log.OccurredAt = log.CreatedAt
		}
		log.Status = pushStatusName(status)
		if log.UpdatedAt == 0 {
			log.UpdatedAt = time.Now().Unix()
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func pushStatusName(status int) string {
	switch status {
	case 0:
		return "pending"
	case 2:
		return "pushed"
	case 3:
		return "failed"
	default:
		return "unknown"
	}
}
