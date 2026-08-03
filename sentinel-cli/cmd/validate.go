package cmd

import (
	"fmt"
	"strings"
)

// validTiers are the four SENTINEL security tiers.
var validTiers = []string{"daily", "authority", "hacker", "military"}

// validFormats are the report formats the analyzer can render.
var validFormats = []string{"json", "pdf", "sarif"}

// isValidTier reports whether t is one of the four SENTINEL security tiers.
func isValidTier(t string) bool {
	for _, v := range validTiers {
		if t == v {
			return true
		}
	}
	return false
}

// parseFormats validates a comma-separated list of report formats and returns
// the deduplicated list in request order. When allowAll is true the literal
// value "all" expands to every supported format (used by the report command).
func parseFormats(s string, allowAll bool) ([]string, error) {
	allowed := strings.Join(validFormats, "|")
	choices := allowed
	if allowAll {
		choices += "|all"
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		f := strings.TrimSpace(part)
		if f == "" {
			return nil, fmt.Errorf("invalid format list %q: empty element (choose %s)", s, choices)
		}
		if allowAll && f == "all" {
			for _, v := range validFormats {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
			continue
		}
		ok := false
		for _, v := range validFormats {
			if f == v {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("invalid format %q: must be one of %s", f, choices)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// requireFlag returns a clean error when a mandatory string flag is empty.
func requireFlag(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("required flag --%s not provided", name)
	}
	return nil
}
