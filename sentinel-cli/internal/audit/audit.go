// Package audit appends one JSON line per scan attempt to the SENTINEL audit
// log (~/.sentinel/audit.log). Every scan attempt is recorded, including
// attempts aborted at the scope gate.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Confirmation methods recorded in the audit log.
const (
	// MethodTyped means the operator typed CONFIRM at the scope gate.
	MethodTyped = "typed-CONFIRM"
	// MethodYesFlag means the operator bypassed the gate with --yes (tests/CI).
	MethodYesFlag = "--yes"
)

// Outcomes recorded in the audit log.
const (
	// OutcomeConfirmed means the scope gate authorized the scan.
	OutcomeConfirmed = "confirmed"
	// OutcomeAborted means the operator failed or declined the scope gate.
	OutcomeAborted = "aborted"
)

// Entry is a single audit record. It serializes as one JSON object per line;
// the timestamp is RFC3339 (via encoding/json on time.Time).
type Entry struct {
	// Timestamp is when the scan attempt was gated. Zero means "now".
	Timestamp time.Time `json:"timestamp"`
	// Target is the validated CIDR range or IP address.
	Target string `json:"target"`
	// Tier is the security tier of the attempted scan.
	Tier string `json:"tier"`
	// ConfirmMethod is how the scope gate was satisfied (MethodTyped or MethodYesFlag).
	ConfirmMethod string `json:"confirm_method"`
	// Outcome is OutcomeConfirmed or OutcomeAborted.
	Outcome string `json:"outcome"`
}

// Log appends e as a single JSON line to the audit log at path, creating the
// parent directory (mode 0700) and the log file (mode 0600) when necessary.
// The log is append-only: existing content is never truncated.
func Log(path string, e Entry) error {
	if path == "" {
		return fmt.Errorf("audit: empty log path")
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encoding entry: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("audit: creating log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: opening %q: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: writing entry to %q: %w", path, err)
	}
	return nil
}
