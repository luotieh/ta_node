package queue

import (
	"database/sql"
	"encoding/json"
	"ta_node/internal/event"
)

func summarize(ev event.ThreatEvent) event.ThreatEvent {
	out := event.ThreatEvent{EventID: ev.EventID, EventTime: ev.EventTime, EventName: ev.EventName, Severity: ev.Severity,
		IOCType: ev.IOCType, IOCValue: ev.IOCValue, SrcIP: ev.SrcIP, SrcPort: ev.SrcPort, DstIP: ev.DstIP, DstPort: ev.DstPort,
		SessionID: ev.SessionID, TransactionID: ev.TransactionID, ContextRevision: ev.ContextRevision, ContextFinal: ev.ContextFinal, SessionSummary: ev.SessionSummary}
	if ev.RawPacket != nil {
		out.RawPacket = &event.RawPacketContext{MessageDirection: ev.RawPacket.MessageDirection}
	}
	if ev.Exchange != nil {
		out.Exchange = &event.ExchangeContext{ResponseStatus: ev.Exchange.ResponseStatus}
	}
	return out
}
func saveSummary(tx *sql.Tx, key string, ev event.ThreatEvent) error {
	b, err := json.Marshal(summarize(ev))
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT OR REPLACE INTO queue_summary(event_id,payload) VALUES(?,?)", key, string(b))
	return err
}
func summaryColumns(tx *sql.Tx, summary bool) (string, error) {
	if !summary {
		return recordColumns, nil
	}
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_summary'").Scan(&exists); err != nil {
		return "", err
	}
	if exists == 0 {
		return recordColumns, nil
	}
	return "id,event_id,event_time,COALESCE((SELECT s.payload FROM queue_summary s WHERE s.event_id=event_queue.event_id),payload),status,retry_count,COALESCE(last_error,''),COALESCE(created_at,0),COALESCE(updated_at,0)", nil
}
