package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/queue"
)

type Client struct {
	url    string
	apiKey string
	http   *http.Client
}

func NewClient(url, apiKey string, timeout time.Duration) *Client {
	return &Client{url: url, apiKey: apiKey, http: &http.Client{Timeout: timeout}}
}

func (c *Client) PushEvent(ctx context.Context, ev event.ThreatEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include a bounded snippet of the response body: management
		// rejections (e.g. 400) carry the reason here, which is otherwise
		// invisible in the push log's last_error.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if msg := strings.TrimSpace(string(snippet)); msg != "" {
			return fmt.Errorf("management returned %s: %s", resp.Status, msg)
		}
		return fmt.Errorf("management returned %s", resp.Status)
	}
	return nil
}

func StartWorker(ctx context.Context, q queue.EventQueue, c *Client, batch int, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		drain(ctx, q, c, batch)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func drain(ctx context.Context, q queue.EventQueue, c *Client, batch int) {
	if lazy, ok := q.(interface {
		PendingIDs(int) ([]int64, error)
		LoadEvent(int64) (event.ThreatEvent, error)
	}); ok {
		ids, err := lazy.PendingIDs(batch)
		if err != nil {
			log.Printf("load pending events: %v", err)
			return
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			ev, err := lazy.LoadEvent(id)
			if err != nil {
				log.Printf("restore queued event %d: %v", id, err)
				continue
			}
			sendOne(ctx, q, c, ev)
		}
		return
	}

	events, err := q.LoadPending(batch)
	if err != nil {
		return
	}
	for _, ev := range events {
		sendOne(ctx, q, c, ev)
	}
}
func sendOne(ctx context.Context, q queue.EventQueue, c *Client, ev event.ThreatEvent) {
	if err := c.PushEvent(ctx, ev); err != nil {
		if e := q.MarkFailed(ev.EventID, ev.ContextRevision, err.Error()); e != nil {
			log.Printf("mark failed: %v", e)
		}
		return
	}
	if err := q.MarkPushed(ev.EventID, ev.ContextRevision); err != nil {
		log.Printf("mark pushed: %v", err)
	}
}
