// Package cmd implements the sentinel-cli command-line interface: the scan,
// analyze and report subcommands, the CONFIRM scope gate, and audit logging.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinel/sentinel-cli/internal/confirm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Exit codes defined by the SENTINEL CLI contract.
const (
	// ExitOK indicates success.
	ExitOK = 0
	// ExitError indicates a failure (validation, scanner, analyzer, I/O).
	ExitError = 1
	// ExitAborted indicates the operator did not confirm the scope gate.
	ExitAborted = 2
)

const (
	// defaultAnalyzerURL is used when --analyzer-url, SENTINEL_ANALYZER_URL
	// and the config file are all unset.
	defaultAnalyzerURL = "http://localhost:8710"
	// defaultScannerPath is used when --scanner and SENTINEL_SCANNER are unset.
	defaultScannerPath = "./sentinel-scanner/target/release/sentinel-scanner"
)

// cfgFile is the optional explicit config file path from --config.
var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "sentinel-cli",
	Short: "SENTINEL vulnerability assessment platform CLI",
	Long: `sentinel-cli drives the SENTINEL vulnerability assessment pipeline:
it runs the sentinel-scanner binary against an authorized target scope, posts
the scan to sentinel-analyzer for risk analysis, and fetches rendered reports
(JSON, PDF, SARIF).

Authorized security testing only. Every scan attempt is gated by an operator
CONFIRM prompt and recorded in ~/.sentinel/audit.log.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command and returns the process exit code per the CLI
// contract: 0 ok, 1 error, 2 aborted at the scope gate.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, confirm.ErrAborted) {
			fmt.Fprintf(os.Stderr, "sentinel-cli: %v\n", err)
			return ExitAborted
		}
		fmt.Fprintf(os.Stderr, "sentinel-cli: error: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func init() {
	cobra.OnInitialize(initConfig)
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default ~/.sentinel/config.yaml)")
	pf.String("analyzer-url", defaultAnalyzerURL, "sentinel-analyzer base URL (env SENTINEL_ANALYZER_URL)")
	must(viper.BindPFlag("analyzer-url", pf.Lookup("analyzer-url")))
}

// initConfig loads ~/.sentinel/config.yaml (or --config) and wires
// SENTINEL_* environment variables into viper. A missing default config file
// is not an error.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			viper.AddConfigPath(filepath.Join(home, ".sentinel"))
		}
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}
	viper.SetEnvPrefix("SENTINEL")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			fmt.Fprintf(os.Stderr, "sentinel-cli: warning: reading config file: %v\n", err)
		}
	}
}

// analyzerURL resolves the analyzer base URL from flag, env, config, or default.
func analyzerURL() string { return viper.GetString("analyzer-url") }

// scannerPath resolves the scanner binary path from --scanner,
// SENTINEL_SCANNER, config, or the contract default.
func scannerPath() string {
	if v := strings.TrimSpace(viper.GetString("scanner")); v != "" {
		return v
	}
	return defaultScannerPath
}

// auditLogPath returns the append-only audit log location.
func auditLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory for audit log: %w", err)
	}
	return filepath.Join(home, ".sentinel", "audit.log"), nil
}

// must panics on programmer errors during command wiring (init-time only).
func must(err error) {
	if err != nil {
		panic(err)
	}
}
