package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sentinel/sentinel-cli/internal/audit"
	"github.com/sentinel/sentinel-cli/internal/client"
	"github.com/sentinel/sentinel-cli/internal/confirm"
	"github.com/sentinel/sentinel-cli/internal/scope"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a scoped vulnerability scan and fetch a report",
	Long: `scan validates the target scope, requires the operator to authorize it at the
CONFIRM scope gate, records the attempt in the audit log, runs the
sentinel-scanner binary, posts the resulting scan.json to sentinel-analyzer,
and writes the requested report to ./sentinel-report.<ext>.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(cmd)
	},
}

func init() {
	f := scanCmd.Flags()
	f.String("target", "", "target CIDR range or IP address to scan (required)")
	f.String("tier", "", "security tier: daily|authority|hacker|military (required)")
	f.String("output", "", "report format: json|pdf|sarif (required, comma-separated list allowed)")
	f.Bool("no-llm", false, "skip LLM analysis; the analyzer uses its rule-based fallback engine")
	f.Bool("yes", false, "bypass the CONFIRM scope gate (tests/CI only; logged in the audit log)")
	f.String("scanner", "", "path to the sentinel-scanner binary (env SENTINEL_SCANNER)")
	must(viper.BindPFlag("scanner", f.Lookup("scanner")))
	rootCmd.AddCommand(scanCmd)
}

// runScan executes the full scan pipeline. It returns confirm.ErrAborted
// (exit code 2) when the operator fails the scope gate, and a wrapped error
// (exit code 1) for any other failure.
func runScan(cmd *cobra.Command) error {
	flags := cmd.Flags()
	target, _ := flags.GetString("target")
	tier, _ := flags.GetString("tier")
	output, _ := flags.GetString("output")
	noLLM, _ := flags.GetBool("no-llm")
	yes, _ := flags.GetBool("yes")

	// 1. Validate inputs: required flags present, target parses, enums valid.
	if err := requireFlag("target", target); err != nil {
		return err
	}
	if err := requireFlag("tier", tier); err != nil {
		return err
	}
	if err := requireFlag("output", output); err != nil {
		return err
	}
	tgt, err := scope.Parse(target)
	if err != nil {
		return err
	}
	if !isValidTier(tier) {
		return fmt.Errorf("invalid tier %q: must be one of daily|authority|hacker|military", tier)
	}
	formats, err := parseFormats(output, false)
	if err != nil {
		return err
	}

	// 2. Scope gate: the operator must type CONFIRM, unless --yes bypasses it
	//    (tests/CI only — the bypass is announced and audit-logged).
	confirmMethod := audit.MethodTyped
	if yes {
		confirmMethod = audit.MethodYesFlag
		fmt.Fprintln(os.Stderr, "sentinel-cli: WARNING: --yes bypassed the CONFIRM scope gate (intended for tests/CI only)")
	} else {
		summary := confirm.Summary{Target: tgt.String(), Tier: tier, HostCount: tgt.HostCount().String()}
		if err := confirm.Gate(os.Stdin, os.Stdout, summary); err != nil {
			auditScanAttempt(tgt.String(), tier, confirmMethod, audit.OutcomeAborted)
			return err
		}
	}

	// 3. Audit the confirmed attempt. The audit log is a compliance control:
	//    if it cannot be written the scan does not proceed.
	if err := logScanAttempt(tgt.String(), tier, confirmMethod, audit.OutcomeConfirmed); err != nil {
		return err
	}

	// Allow Ctrl-C to cancel the scanner child process and HTTP requests.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 4. Run the scanner binary into a temporary scan.json.
	scanJSON, err := runScanner(ctx, scannerPath(), tgt.String(), tier)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sentinel-cli: scan complete (%d bytes of scan data)\n", len(scanJSON))

	// 5. Analyze. --no-llm still POSTs; the analyzer falls back automatically.
	c, err := client.New(analyzerURL())
	if err != nil {
		return err
	}
	analysisJSON, err := c.Analyze(ctx, scanJSON, noLLM)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sentinel-cli: analysis complete (%d bytes of analysis data)\n", len(analysisJSON))

	// 6. Render the requested report(s) and copy them into the working directory.
	files, err := c.Report(ctx, scanJSON, analysisJSON, formats)
	if err != nil {
		return err
	}
	for _, format := range formats {
		if err := saveReport(files, format); err != nil {
			return err
		}
	}
	return nil
}

// runScanner invokes the scanner binary, pointing it at a temporary
// scan.json, and returns the file's contents.
func runScanner(ctx context.Context, binPath, target, tier string) ([]byte, error) {
	if _, err := os.Stat(binPath); err != nil {
		return nil, fmt.Errorf("scanner binary not found at %q (set --scanner or SENTINEL_SCANNER): %w", binPath, err)
	}
	dir, err := os.MkdirTemp("", "sentinel-scan-")
	if err != nil {
		return nil, fmt.Errorf("creating temporary scan directory: %w", err)
	}
	defer os.RemoveAll(dir)

	outPath := filepath.Join(dir, "scan.json")
	fmt.Fprintf(os.Stderr, "sentinel-cli: running scanner %q against %s (tier %s)\n", binPath, target, tier)
	scanCmd := exec.CommandContext(ctx, binPath, "--target", target, "--tier", tier, "--output", outPath)
	scanCmd.Stdout = os.Stdout
	scanCmd.Stderr = os.Stderr
	if err := scanCmd.Run(); err != nil {
		return nil, fmt.Errorf("scanner %q failed: %w", binPath, err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("reading scanner output %q: %w", outPath, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("scanner %q produced an empty scan file %q", binPath, outPath)
	}
	return data, nil
}

// saveReport copies the analyzer-generated report file for format to
// ./sentinel-report.<format>.
func saveReport(files map[string]string, format string) error {
	src, ok := files[format]
	if !ok || src == "" {
		return fmt.Errorf("analyzer did not return a %s report file", format)
	}
	dst := fmt.Sprintf("sentinel-report.%s", format)
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copying %s report from %q: %w", format, src, err)
	}
	fmt.Fprintf(os.Stdout, "sentinel-cli: %s report written to %s\n", format, dst)
	return nil
}

// copyFile copies a single file, creating or truncating dst.
func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	_, err = out.ReadFrom(in)
	return err
}

// logScanAttempt appends one entry to the audit log; a write failure is a
// hard error for confirmed scans.
func logScanAttempt(target, tier, method, outcome string) error {
	path, err := auditLogPath()
	if err != nil {
		return fmt.Errorf("audit logging scan attempt: %w", err)
	}
	entry := audit.Entry{
		Timestamp:     time.Now(),
		Target:        target,
		Tier:          tier,
		ConfirmMethod: method,
		Outcome:       outcome,
	}
	if err := audit.Log(path, entry); err != nil {
		return fmt.Errorf("audit logging scan attempt: %w", err)
	}
	return nil
}

// auditScanAttempt is best-effort: it warns instead of failing so the real
// outcome (usually an operator abort) is not masked by a logging problem.
func auditScanAttempt(target, tier, method, outcome string) {
	if err := logScanAttempt(target, tier, method, outcome); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel-cli: warning: %v\n", err)
	}
}
