package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/sentinel/sentinel-cli/internal/client"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Render reports from an existing scan.json and analysis.json",
	Long: `report posts a scan.json and analysis.json pair to the
sentinel-analyzer /report endpoint and copies each rendered report into the
working directory as ./sentinel-report.<ext>.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReport(cmd)
	},
}

func init() {
	f := reportCmd.Flags()
	f.String("scan", "", "path to a scanner output file (scan.json) (required)")
	f.String("analysis", "", "path to an analyzer output file (analysis.json) (required)")
	f.String("format", "", "report format: json|pdf|sarif|all (required, comma-separated list allowed)")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command) error {
	flags := cmd.Flags()
	scanPath, _ := flags.GetString("scan")
	analysisPath, _ := flags.GetString("analysis")
	format, _ := flags.GetString("format")

	if err := requireFlag("scan", scanPath); err != nil {
		return err
	}
	if err := requireFlag("analysis", analysisPath); err != nil {
		return err
	}
	if err := requireFlag("format", format); err != nil {
		return err
	}
	formats, err := parseFormats(format, true)
	if err != nil {
		return err
	}

	scanJSON, err := os.ReadFile(scanPath)
	if err != nil {
		return fmt.Errorf("reading scan file %q: %w", scanPath, err)
	}
	analysisJSON, err := os.ReadFile(analysisPath)
	if err != nil {
		return fmt.Errorf("reading analysis file %q: %w", analysisPath, err)
	}

	c, err := client.New(analyzerURL())
	if err != nil {
		return err
	}
	files, err := c.Report(context.Background(), scanJSON, analysisJSON, formats)
	if err != nil {
		return err
	}
	for _, f := range formats {
		if err := saveReport(files, f); err != nil {
			return err
		}
	}
	return nil
}
