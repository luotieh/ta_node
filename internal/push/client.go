package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ta_node/internal/event"
	"ta_node/internal/queue"
)

type Client struct {
	url    string
	token  string
	apiKey string
	http   *http.Client
}

func NewClient(url, token, apiKey string, timeout time.Duration) *Client {
	return &Client{url: url, token: token, apiKey: apiKey, http: &http.Client{Timeout: timeout}}
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
