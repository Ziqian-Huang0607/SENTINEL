// sentinel-cli is the operator command-line interface of the SENTINEL
// vulnerability assessment platform. It gates every scan behind an operator
// CONFIRM prompt, audit-logs every scan attempt, drives the sentinel-scanner
// binary, and talks to the sentinel-analyzer REST API for analysis and
// report rendering.
//
// Exit codes (contract): 0 ok, 1 error, 2 aborted at the scope gate.
package main

import (
	"os"

	"github.com/sentinel/sentinel-cli/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
