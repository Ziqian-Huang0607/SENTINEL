// Package confirm implements the SENTINEL scope gate: before any scan the
// operator is shown the target scope and a legal warning, and must type the
// exact word CONFIRM to proceed.
package confirm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Phrase is the exact word the operator must type to authorize a scan.
const Phrase = "CONFIRM"

// LegalWarning is printed before every scan. It must stay intact: the scope
// gate is a compliance control, not a courtesy prompt.
const LegalWarning = "Authorized security testing only."

// ErrAborted is returned when the operator does not type the confirmation
// phrase exactly. Callers map it to the contract's exit code 2 (aborted).
var ErrAborted = errors.New("scan aborted: scope not confirmed by operator")

// Summary describes the scan the operator is asked to authorize.
type Summary struct {
	// Target is the validated CIDR range or IP address.
	Target string
	// Tier is the security tier of the scan (daily, authority, hacker, military).
	Tier string
	// HostCount is the estimated number of addressable hosts in the target.
	HostCount string
}

// Gate prints the scope summary and legal warning to out, then reads one line
// from in. It returns nil only when the line is exactly Phrase ("CONFIRM");
// any other input — including end of input — yields ErrAborted. A genuine I/O
// failure while reading is returned as a distinct wrapped error so callers can
// tell it apart from an operator abort.
func Gate(in io.Reader, out io.Writer, s Summary) error {
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "================= SENTINEL SCOPE GATE =================")
	fmt.Fprintf(out, "Target:           %s\n", s.Target)
	fmt.Fprintf(out, "Tier:             %s\n", s.Tier)
	fmt.Fprintf(out, "Estimated hosts:  %s\n", s.HostCount)
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "WARNING: %s\n", LegalWarning)
	fmt.Fprintln(out, "Scanning networks or systems without explicit written authorization")
	fmt.Fprintln(out, "is illegal. By proceeding you assert that you are authorized to test")
	fmt.Fprintln(out, "the target scope shown above.")
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "Type %s to proceed: ", Phrase)

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("confirm: reading operator input: %w", err)
	}
	got := strings.TrimRight(line, "\r\n")
	if got != Phrase {
		fmt.Fprintln(out, "Aborted.")
		return fmt.Errorf("%w: expected %q, got %q", ErrAborted, Phrase, got)
	}
	fmt.Fprintln(out, "Scope confirmed.")
	return nil
}
