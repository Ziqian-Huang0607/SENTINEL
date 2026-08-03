package cmd

import (
	"reflect"
	"testing"
)

func TestIsValidTier(t *testing.T) {
	tests := []struct {
		tier string
		want bool
	}{
		{"daily", true},
		{"authority", true},
		{"hacker", true},
		{"military", true},
		{"Daily", false},
		{"DAILY", false},
		{"weekly", false},
		{"", false},
		{"daily ", false},
	}
	for _, tc := range tests {
		t.Run(tc.tier, func(t *testing.T) {
			if got := isValidTier(tc.tier); got != tc.want {
				t.Errorf("isValidTier(%q) = %v, want %v", tc.tier, got, tc.want)
			}
		})
	}
}

func TestParseFormats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		allowAll bool
		want     []string
		wantErr  bool
	}{
		{"json", "json", false, []string{"json"}, false},
		{"pdf", "pdf", false, []string{"pdf"}, false},
		{"sarif", "sarif", false, []string{"sarif"}, false},
		{"comma list", "json,pdf", false, []string{"json", "pdf"}, false},
		{"spaces tolerated", "json, sarif", false, []string{"json", "sarif"}, false},
		{"deduped", "json,json", false, []string{"json"}, false},
		{"all expands when allowed", "all", true, []string{"json", "pdf", "sarif"}, false},
		{"all rejected when not allowed", "all", false, nil, true},
		{"invalid", "xml", false, nil, true},
		{"invalid in list", "json,xml", false, nil, true},
		{"uppercase", "JSON", false, nil, true},
		{"empty", "", false, nil, true},
		{"empty element", "json,,pdf", false, nil, true},
		{"trailing comma", "json,", false, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFormats(tc.input, tc.allowAll)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFormats(%q, %v) = %v, nil error; want error", tc.input, tc.allowAll, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFormats(%q, %v) error = %v", tc.input, tc.allowAll, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseFormats(%q, %v) = %v, want %v", tc.input, tc.allowAll, got, tc.want)
			}
		})
	}
}

func TestRequireFlag(t *testing.T) {
	if err := requireFlag("target", "192.168.1.0/24"); err != nil {
		t.Errorf("requireFlag with value = %v, want nil", err)
	}
	if err := requireFlag("target", ""); err == nil {
		t.Error("requireFlag with empty value = nil, want error")
	}
	if err := requireFlag("target", "   "); err == nil {
		t.Error("requireFlag with whitespace value = nil, want error")
	}
}
