package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	testScan     = []byte(`{"scan_id":"00000000-0000-0000-0000-000000000001","target":"127.0.0.1","tier":"daily","hosts":[],"vulnerabilities":[],"risk_score":0}`)
	testAnalysis = []byte(`{"attack_chains":[],"remediation":{},"risk_score":0,"observations":[],"analyzer_mode":"fallback"}`)
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{"http localhost", "http://localhost:8710", false},
		{"https with path", "https://analyzer.internal:8710/base", false},
		{"trailing slash trimmed", "http://localhost:8710/", false},
		{"empty", "", true},
		{"no scheme", "localhost:8710", true},
		{"unsupported scheme", "ftp://localhost:8710", true},
		{"not a url", "://nope", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.baseURL)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(%q) = %+v, nil error; want error", tc.baseURL, c)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) error = %v", tc.baseURL, err)
			}
			if strings.HasSuffix(c.BaseURL(), "/") {
				t.Errorf("New(%q).BaseURL() = %q, want no trailing slash", tc.baseURL, c.BaseURL())
			}
		})
	}
}

func TestClientTimeout(t *testing.T) {
	c, err := New("http://localhost:8710")
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if c.http.Timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", c.http.Timeout, DefaultTimeout)
	}
	if DefaultTimeout != 15*time.Minute {
		t.Errorf("DefaultTimeout = %v, want 15m (LLM inference budget)", DefaultTimeout)
	}
}

func TestAnalyzeSuccess(t *testing.T) {
	var gotNoLLM string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		gotNoLLM = r.Header.Get(NoLLMHeader)
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(testScan) {
			t.Errorf("analyzer received %s, want %s", body, testScan)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testAnalysis)
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	out, err := c.Analyze(context.Background(), testScan, true)
	if err != nil {
		t.Fatalf("Analyze(): %v", err)
	}
	if string(out) != string(testAnalysis) {
		t.Errorf("Analyze() = %s, want %s", out, testAnalysis)
	}
	if gotNoLLM != "true" {
		t.Errorf("%s header = %q, want %q", NoLLMHeader, gotNoLLM, "true")
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
}

func TestAnalyzeNoLLMHeaderAbsentByDefault(t *testing.T) {
	headerSeen := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, headerSeen = r.Header[http.CanonicalHeaderKey(NoLLMHeader)]
		_, _ = w.Write(testAnalysis)
	}))
	defer srv.Close()

	c, _ := New(srv.URL)
	if _, err := c.Analyze(context.Background(), testScan, false); err != nil {
		t.Fatalf("Analyze(): %v", err)
	}
	if headerSeen {
		t.Errorf("%s header present though noLLM=false", NoLLMHeader)
	}
}

func TestAnalyzeValidationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":[{"loc":["body","tier"],"msg":"field required"}]}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL)
	_, err := c.Analyze(context.Background(), testScan, false)
	if err == nil {
		t.Fatal("Analyze() = nil error, want 422 error")
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("error %q missing status code", err)
	}
	if !strings.Contains(err.Error(), "field required") {
		t.Errorf("error %q missing analyzer detail", err)
	}
}

func TestAnalyzeRejectsInvalidJSON(t *testing.T) {
	c, _ := New("http://localhost:8710")
	if _, err := c.Analyze(context.Background(), []byte("not json"), false); err == nil {
		t.Error("Analyze(invalid JSON) = nil error, want error")
	}
}

func TestReportSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/report" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		var req reportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding report request: %v", err)
		}
		if len(req.Formats) != 2 || req.Formats[0] != "pdf" || req.Formats[1] != "sarif" {
			t.Errorf("formats = %v, want [pdf sarif]", req.Formats)
		}
		if string(req.Scan) != string(testScan) {
			t.Errorf("scan = %s, want %s", req.Scan, testScan)
		}
		if string(req.Analysis) != string(testAnalysis) {
			t.Errorf("analysis = %s, want %s", req.Analysis, testAnalysis)
		}
		_, _ = w.Write([]byte(`{"files":{"pdf":"/tmp/r.pdf","sarif":"/tmp/r.sarif"}}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL)
	files, err := c.Report(context.Background(), testScan, testAnalysis, []string{"pdf", "sarif"})
	if err != nil {
		t.Fatalf("Report(): %v", err)
	}
	if files["pdf"] != "/tmp/r.pdf" || files["sarif"] != "/tmp/r.sarif" {
		t.Errorf("Report() files = %v", files)
	}
}

func TestReportErrors(t *testing.T) {
	c, _ := New("http://localhost:8710")
	tests := []struct {
		name     string
		scan     []byte
		analysis []byte
		formats  []string
	}{
		{"invalid scan json", []byte("{"), testAnalysis, []string{"pdf"}},
		{"invalid analysis json", testScan, []byte("{"), []string{"pdf"}},
		{"no formats", testScan, testAnalysis, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Report(context.Background(), tc.scan, tc.analysis, tc.formats); err == nil {
				t.Error("Report() = nil error, want error")
			}
		})
	}
}

func TestReportEmptyFilesMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"files":{}}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL)
	if _, err := c.Report(context.Background(), testScan, testAnalysis, []string{"pdf"}); err == nil {
		t.Error("Report() = nil error, want error for empty files map")
	}
}

func TestUnreachableAnalyzer(t *testing.T) {
	// Port 1 is reserved and refuses connections on loopback.
	c, _ := New("http://127.0.0.1:1")
	_, err := c.Analyze(context.Background(), testScan, false)
	if err == nil {
		t.Fatal("Analyze() = nil error, want connection error")
	}
	if !strings.Contains(err.Error(), "client: POST") {
		t.Errorf("error %q missing wrapped context", err)
	}
}

func TestTimeoutFromEnv(t *testing.T) {
	orig := getenv
	defer func() { getenv = orig }()

	getenv = func(string) string { return "" }
	if got := timeoutFromEnv(); got != DefaultTimeout {
		t.Fatalf("unset env: got %v, want %v", got, DefaultTimeout)
	}
	getenv = func(string) string { return "45" }
	if got := timeoutFromEnv(); got != 45*time.Second {
		t.Fatalf("env 45: got %v, want 45s", got)
	}
	getenv = func(string) string { return "garbage" }
	if got := timeoutFromEnv(); got != DefaultTimeout {
		t.Fatalf("invalid env: got %v, want %v", got, DefaultTimeout)
	}
}
