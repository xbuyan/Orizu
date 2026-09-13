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

// Client posts sealed alert blobs to a relay server over HTTP, and
// fetches them back.
type Client struct {
	baseURL    string
	postToken  string // sent as a Bearer token on Post only; Fetch needs none
	httpClient *http.Client
}

// NewClient creates a Client targeting baseURL (e.g.
// "https://relay.example.com"). postToken is required for Post to
// succeed against a real relay.Server (see relay.Server's package doc
// for why POST is authenticated but GET is not) — pass an empty string
// for a client that will only ever call Fetch, such as a guardian's.
func NewClient(baseURL string, postToken string) *Client {
	return &Client{
		baseURL:    baseURL,
		postToken:  postToken,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Post sends a sealed blob for guardianID to the relay, authenticated
// with the client's postToken. It returns an error if the relay is
// unreachable, rejects the token, or responds with any other non-2xx
// status; callers (e.g. cmd/orizu on a duress check-in) should treat a
// Post failure as "this guardian may not have been notified" and not
// assume silent success.
func (c *Client) Post(guardianID string, blob []byte) error {
	url := fmt.Sprintf("%s/alerts/%s", c.baseURL, guardianID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("relay: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+c.postToken)

	resp, err := c.httpClient.Do(req)
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
// return the same blobs until they expire (see relay.Store). Fetch needs
// no authentication — see relay.Server's package doc for why GET is
// deliberately left open.
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

