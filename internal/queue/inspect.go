package queue

import (
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
	OccurredAt      int64                   `json:"occurred_at"`
	CreatedAt       int64                   `json:"created_at"`
	EventName       string                  `json:"event_name"`
	Severity        string                  `json:"severity"`
	IOCType         string                  `json:"ioc_type,omitempty"`
	IOCValue        string                  `json:"ioc_value,omitempty"`
	SrcIP           string                  `json:"src_ip,omitempty"`
	SrcPort         uint16                  `json:"src_port,omitempty"`
	DstIP           string                  `json:"dst_ip,omitempty"`
	DstPort         uint16                  `json:"dst_port,omitempty"`
	RawPacket       *event.RawPacketContext `json:"raw_packet,omitempty"`
	SessionID       string                  `json:"session_id,omitempty"`
	TransactionID   string                  `json:"transaction_id,omitempty"`
	ContextRevision uint64                  `json:"context_revision,omitempty"`
	ContextFinal    bool                    `json:"context_final,omitempty"`
	Exchange        *event.ExchangeContext  `json:"exchange,omitempty"`
	SessionSummary  *event.SessionSummary   `json:"session_summary,omitempty"`
	Status          string                  `json:"status"`
	RetryCount      int                     `json:"retry_count"`
	LastError       string                  `json:"last_error,omitempty"`
	UpdatedAt       int64                   `json:"updated_at"`
}

func RecentPushLogs(path string, limit int) ([]PushLog, error) {
	return recentPushLogs(path, limit, false)
}
func RecentPushSummaries(path string, limit int) ([]PushLog, error) {
	return recentPushLogs(path, limit, true)
}
func recentPushLogs(path string, limit int, summary bool) ([]PushLog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	records, err := recentRecords(path, limit*4, summary)
	if err != nil {
		return nil, err
	}
	var logs []PushLog
	seen := map[string]bool{}
	for _, rec := range records {
		payload := rec.Payload
		status := rec.Status
		log := PushLog{EventID: rec.Key, EventTime: rec.Time, RetryCount: rec.Retry, LastError: rec.Error, CreatedAt: rec.Created, UpdatedAt: rec.Updated}
		var ev event.ThreatEvent
		decoded := []byte(payload)
		if err := json.Unmarshal(decoded, &ev); err == nil {
			if summary {
				ev = summarize(ev)
			}
			if seen[ev.EventID] {
				continue
			}
			seen[ev.EventID] = true
			log.EventID = ev.EventID
			log.EventName = ev.EventName
			log.Severity = ev.Severity
			log.IOCType = ev.IOCType
			log.IOCValue = ev.IOCValue
			log.SrcIP = ev.SrcIP
			log.SrcPort = ev.SrcPort
			log.DstIP = ev.DstIP
			log.DstPort = ev.DstPort
			log.RawPacket = ev.RawPacket
			log.SessionID = ev.SessionID
			log.TransactionID = ev.TransactionID
			log.ContextRevision = ev.ContextRevision
			log.ContextFinal = ev.ContextFinal
			log.Exchange = ev.Exchange
			log.SessionSummary = ev.SessionSummary
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
		if len(logs) >= limit {
			break
		}
	}
	return logs, nil
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
