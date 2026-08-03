package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var entries []Entry
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d is not a valid JSON audit entry: %v", i+1, err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestLogCreatesAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sentinel", "audit.log")
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

	first := Entry{Timestamp: ts, Target: "192.168.1.0/24", Tier: "daily", ConfirmMethod: MethodTyped, Outcome: OutcomeConfirmed}
	if err := Log(path, first); err != nil {
		t.Fatalf("Log() first entry: %v", err)
	}
	second := Entry{Timestamp: ts.Add(time.Hour), Target: "10.0.0.0/8", Tier: "hacker", ConfirmMethod: MethodYesFlag, Outcome: OutcomeAborted}
	if err := Log(path, second); err != nil {
		t.Fatalf("Log() second entry: %v", err)
	}

	entries := readEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0] != first {
		t.Errorf("entry[0] = %+v, want %+v", entries[0], first)
	}
	if entries[1] != second {
		t.Errorf("entry[1] = %+v, want %+v", entries[1], second)
	}
}

func TestLogTimestampIsRFC3339AndDefaultsToNow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	before := time.Now()
	if err := Log(path, Entry{Target: "127.0.0.1", Tier: "daily", ConfirmMethod: MethodTyped, Outcome: OutcomeConfirmed}); err != nil {
		t.Fatalf("Log(): %v", err)
	}
	after := time.Now()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var raw struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("audit line is not JSON: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", raw.Timestamp, err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Errorf("default timestamp %v not between %v and %v", parsed, before, after)
	}
}

func TestLogFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".sentinel", "audit.log")
	if err := Log(path, Entry{Target: "127.0.0.1", Tier: "daily", ConfirmMethod: MethodTyped, Outcome: OutcomeConfirmed}); err != nil {
		t.Fatalf("Log(): %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit log mode = %o, want 600", perm)
	}
}

func TestLogEmptyPath(t *testing.T) {
	if err := Log("", Entry{}); err == nil {
		t.Error("Log(\"\") = nil, want error")
	}
}

func TestLogUnwritableDir(t *testing.T) {
	dir := t.TempDir()
	ro := filepath.Join(dir, "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := Log(filepath.Join(ro, "audit.log"), Entry{Target: "127.0.0.1", Tier: "daily", ConfirmMethod: MethodTyped, Outcome: OutcomeConfirmed})
	if err == nil {
		t.Skip("running with sufficient privileges to write a read-only directory; skipping")
	}
	if !strings.Contains(err.Error(), "audit:") {
		t.Errorf("error %q missing package context", err)
	}
}
