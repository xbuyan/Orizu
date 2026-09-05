package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// Fetch retrieves every non-expired sealed blob stored for guardianID.
// Blobs are returned as raw bytes, decoded from the relay's base64 JSON
// response — callers pass each one to alert.Open for decryption. Fetch
// does not delete or acknowledge anything server-side; repeated calls may
// return the same blobs until they expire (see relay.Store).
func (c *Client) Fetch(guardianID string) ([][]byte, error) {
	url := fmt.Sprintf("%s/alerts/%s", c.baseURL, guardianID)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("relay: fetching alerts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("relay: unexpected status %d: %s", resp.StatusCode, body)
	}

	var parsed alertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("relay: parsing response: %w", err)
	}

	blobs := make([][]byte, 0, len(parsed.Alerts))
	for _, encoded := range parsed.Alerts {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// Skip a malformed entry rather than fail the whole fetch —
			// one corrupted record shouldn't hide the rest.
			continue
		}
		blobs = append(blobs, decoded)
	}
	return blobs, nil
}

