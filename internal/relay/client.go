package relay

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client posts sealed alert blobs to a relay server over HTTP.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Client targeting baseURL (e.g. "https://relay.example.com").
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Post sends a sealed blob for guardianID to the relay. It returns an
// error if the relay is unreachable or responds with a non-2xx status;
// callers (e.g. cmd/orizu on a duress check-in) should treat a Post
// failure as "this guardian may not have been notified" and not assume
// silent success.
func (c *Client) Post(guardianID string, blob []byte) error {
	url := fmt.Sprintf("%s/alerts/%s", c.baseURL, guardianID)
	resp, err := c.httpClient.Post(url, "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("relay: posting alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("relay: unexpected status %d: %s", resp.StatusCode, body)
	}
	return nil
}

