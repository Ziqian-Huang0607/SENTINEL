package scope

import (
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		isCIDR bool
	}{
		{"ipv4 cidr", "192.168.1.0/24", true},
		{"ipv4 cidr with host bits", "192.168.1.45/24", true},
		{"ipv4 single", "192.168.1.45", false},
		{"ipv4 loopback", "127.0.0.1", false},
		{"ipv6 cidr", "fd00::/64", true},
		{"ipv6 single", "::1", false},
		{"ipv6 single full", "2001:db8::1", false},
		{"host route", "10.0.0.1/32", true},
		{"surrounding whitespace", "  10.0.0.0/8  ", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgt, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("Parse(%q) returned unexpected error: %v", tc.raw, err)
			}
			if tgt.IsCIDR() != tc.isCIDR {
				t.Errorf("Parse(%q).IsCIDR() = %v, want %v", tc.raw, tgt.IsCIDR(), tc.isCIDR)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"hostname", "db01.example.com"},
		{"wildcard", "192.168.1.*"},
		{"bad octet", "192.168.1.256"},
		{"truncated ipv4", "192.168.1"},
		{"bad prefix length", "192.168.1.0/33"},
		{"negative prefix length", "192.168.1.0/-1"},
		{"non-numeric prefix length", "192.168.1.0/abc"},
		{"ipv6 zone", "fe80::1%eth0"},
		{"double slash", "10.0.0.0//8"},
		{"port suffix", "192.168.1.1:8080"},
		{"range syntax", "192.168.1.1-192.168.1.10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.raw); err == nil {
				t.Errorf("Parse(%q) succeeded, want error", tc.raw)
			}
		})
	}
}

func TestHostCount(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"single ipv4", "192.168.1.45", "1"},
		{"single ipv6", "fd00::1", "1"},
		{"slash 32", "10.0.0.1/32", "1"},
		{"slash 31 point to point", "10.0.0.0/31", "2"},
		{"slash 30", "10.0.0.0/30", "2"},
		{"slash 24", "192.168.1.0/24", "254"},
		{"slash 24 with host bits", "192.168.1.45/24", "254"},
		{"slash 16", "172.16.0.0/16", "65534"},
		{"slash 8", "10.0.0.0/8", "16777214"},
		{"slash 0", "0.0.0.0/0", "4294967294"},
		{"ipv6 slash 64", "fd00::/64", "18446744073709551616"},
		{"ipv6 slash 128", "fd00::1/128", "1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgt, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("Parse(%q) returned unexpected error: %v", tc.raw, err)
			}
			if got := tgt.HostCount().String(); got != tc.want {
				t.Errorf("Parse(%q).HostCount() = %s, want %s", tc.raw, got, tc.want)
			}
		})
	}
}
