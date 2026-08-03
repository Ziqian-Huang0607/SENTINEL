package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/sentinel/sentinel-cli/internal/client"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze an existing scan.json with sentinel-analyzer",
	Long: `analyze posts an existing scanner output file (scan.json) to the
sentinel-analyzer /analyze endpoint and writes the analyzer's response to
./analysis.json. With --no-llm the analyzer uses its rule-based fallback
engine instead of the LLM.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAnalyze(cmd)
	},
}

func init() {
	f := analyzeCmd.Flags()
	f.String("input", "", "path to a scanner output file (scan.json) (required)")
	f.Bool("no-llm", false, "skip LLM analysis; the analyzer uses its rule-based fallback engine")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command) error {
	flags := cmd.Flags()
	input, _ := flags.GetString("input")
	noLLM, _ := flags.GetBool("no-llm")

	if err := requireFlag("input", input); err != nil {
		return err
	}
	scanJSON, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading scan input %q: %w", input, err)
	}

	c, err := client.New(analyzerURL())
	if err != nil {
		return err
	}
	analysisJSON, err := c.Analyze(context.Background(), scanJSON, noLLM)
	if err != nil {
		return err
	}
	const outPath = "analysis.json"
	if err := os.WriteFile(outPath, analysisJSON, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stdout, "sentinel-cli: analysis written to %s\n", outPath)
	return nil
}
