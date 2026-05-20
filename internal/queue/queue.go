package queue

import "ta_node/internal/event"

type EventQueue interface {
	Enqueue(event.ThreatEvent) error
	LoadPending(limit int) ([]event.ThreatEvent, error)
	MarkPushed(eventID string) error
	MarkFailed(eventID string, errMsg string) error
}
