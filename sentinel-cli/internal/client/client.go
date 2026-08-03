// Package client is the SENTINEL analyzer REST client. It POSTs scan results
// to /analyze and requests rendered reports from /report, with a
// context-rich error wrapping.
//
// Requests time out after DefaultTimeout (15 minutes): when the analyzer runs
// in LLM mode, a single Llama 3.1 8B inference on laptop hardware legitimately
// takes minutes. Override with SENTINEL_HTTP_TIMEOUT_S (seconds).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// getenv is os.Getenv, indirected for tests.
var getenv = os.Getenv

// DefaultTimeout is the maximum duration of any single analyzer request.
// LLM-mode analysis on an 8GB laptop can take several minutes per call, so
// the default is deliberately generous; override via SENTINEL_HTTP_TIMEOUT_S.
const DefaultTimeout = 15 * time.Minute

// timeoutFromEnv honors SENTINEL_HTTP_TIMEOUT_S (integer seconds) when set
// and valid, falling back to DefaultTimeout otherwise.
func timeoutFromEnv() time.Duration {
	if raw := strings.TrimSpace(getenv("SENTINEL_HTTP_TIMEOUT_S")); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return DefaultTimeout
}

// maxResponseBody caps how much of an analyzer response is read (64 MiB).
const maxResponseBody = 64 << 20

// maxErrorSnippet caps how much of an error response body is quoted in errors.
const maxErrorSnippet = 512

// NoLLMHeader tells the analyzer to skip the LLM and use its rule-based
// fallback engine for the request.
const NoLLMHeader = "X-Sentinel-No-LLM"

// Client talks to a sentinel-analyzer instance over HTTP.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a Client for the given analyzer base URL (e.g.
// "http://localhost:8710"). It errors on malformed or non-HTTP(S) URLs.
func New(baseURL string) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("client: invalid analyzer URL %q", baseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("client: unsupported scheme %q in analyzer URL %q", u.Scheme, baseURL)
	}
	return &Client{
		baseURL: strings.TrimRight(u.String(), "/"),
		http:    &http.Client{Timeout: timeoutFromEnv()},
	}, nil
}

// BaseURL returns the normalized analyzer base URL the client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

// Analyze POSTs a scan.json document to /analyze and returns the raw
// analysis.json response body. When noLLM is true the X-Sentinel-No-LLM
// header is set so the analyzer uses its rule-based fallback engine.
func (c *Client) Analyze(ctx context.Context, scanJSON []byte, noLLM bool) ([]byte, error) {
	if !json.Valid(scanJSON) {
		return nil, errors.New("client: analyze: scan input is not valid JSON")
	}
	headers := map[string]string{}
	if noLLM {
		headers[NoLLMHeader] = "true"
	}
	return c.post(ctx, "/analyze", scanJSON, headers)
}

// Report POSTs a scan + analysis pair to /report requesting the given formats
// (e.g. "pdf", "json", "sarif") and returns the analyzer-provided map of
// format to generated file path.
func (c *Client) Report(ctx context.Context, scanJSON, analysisJSON []byte, formats []string) (map[string]string, error) {
	if !json.Valid(scanJSON) {
		return nil, errors.New("client: report: scan input is not valid JSON")
	}
	if !json.Valid(analysisJSON) {
		return nil, errors.New("client: report: analysis input is not valid JSON")
	}
	if len(formats) == 0 {
		return nil, errors.New("client: report: at least one report format is required")
	}
	reqBody, err := json.Marshal(reportRequest{
		Scan:     json.RawMessage(scanJSON),
		Analysis: json.RawMessage(analysisJSON),
		Formats:  formats,
	})
	if err != nil {
		return nil, fmt.Errorf("client: report: encoding request: %w", err)
	}
	data, err := c.post(ctx, "/report", reqBody, nil)
	if err != nil {
		return nil, err
	}
	var resp reportResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("client: report: decoding analyzer response: %w", err)
	}
	if len(resp.Files) == 0 {
		return nil, errors.New("client: report: analyzer response contained no files")
	}
	return resp.Files, nil
}

type reportRequest struct {
	Scan     json.RawMessage `json:"scan"`
	Analysis json.RawMessage `json:"analysis"`
	Formats  []string        `json:"formats"`
}

type reportResponse struct {
	Files map[string]string `json:"files"`
}

// post issues a JSON POST to path and returns the response body. Non-2xx
// responses become errors quoting the analyzer's status and a body snippet.
func (c *Client) post(ctx context.Context, path string, body []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("client: building POST %s request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: POST %s %s: %w", c.baseURL, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("client: reading POST %s response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("client: POST %s %s: analyzer returned %s: %s",
			c.baseURL, path, resp.Status, snippet(data))
	}
	return data, nil
}

// snippet renders a response body for inclusion in an error message.
func snippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > maxErrorSnippet {
		s = s[:maxErrorSnippet] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
