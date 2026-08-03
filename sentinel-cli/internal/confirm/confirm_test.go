package confirm

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testSummary() Summary {
	return Summary{Target: "192.168.1.0/24", Tier: "daily", HostCount: "254"}
}

func TestGate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error // nil means the gate opens
	}{
		{"exact phrase", "CONFIRM\n", nil},
		{"phrase without newline (EOF)", "CONFIRM", nil},
		{"crlf line ending", "CONFIRM\r\n", nil},
		{"lowercase", "confirm\n", ErrAborted},
		{"mixed case", "Confirm\n", ErrAborted},
		{"trailing space", "CONFIRM \n", ErrAborted},
		{"leading space", " CONFIRM\n", ErrAborted},
		{"extra word", "CONFIRM please\n", ErrAborted},
		{"yes instead", "yes\n", ErrAborted},
		{"empty line", "\n", ErrAborted},
		{"immediate EOF", "", ErrAborted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Gate(strings.NewReader(tc.input), &out, testSummary())
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Gate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Gate() error = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
		})
	}
}

func TestGatePrintsScopeAndWarning(t *testing.T) {
	var out bytes.Buffer
	if err := Gate(strings.NewReader("CONFIRM\n"), &out, testSummary()); err != nil {
		t.Fatalf("Gate() = %v, want nil", err)
	}
	printed := out.String()
	for _, want := range []string{"192.168.1.0/24", "daily", "254", LegalWarning, Phrase} {
		if !strings.Contains(printed, want) {
			t.Errorf("gate output missing %q; output was:\n%s", want, printed)
		}
	}
}

// errReader always fails, simulating a broken stdin.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestGateReadErrorIsNotAnAbort(t *testing.T) {
	var out bytes.Buffer
	err := Gate(errReader{}, &out, testSummary())
	if err == nil {
		t.Fatal("Gate() = nil, want error")
	}
	if errors.Is(err, ErrAborted) {
		t.Errorf("Gate() error = %v, must not wrap ErrAborted for I/O failures", err)
	}
}
