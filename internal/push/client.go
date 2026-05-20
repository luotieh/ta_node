package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/queue"
)

type Client struct {
	url   string
	token string
	http  *http.Client
}

func NewClient(url, token string, timeout time.Duration) *Client {
	return &Client{url: url, token: token, http: &http.Client{Timeout: timeout}}
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
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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
	events, err := q.LoadPending(batch)
	if err != nil {
		return
	}
	for _, ev := range events {
		if err := c.PushEvent(ctx, ev); err != nil {
			_ = q.MarkFailed(ev.EventID, err.Error())
			continue
		}
		_ = q.MarkPushed(ev.EventID)
	}
}
