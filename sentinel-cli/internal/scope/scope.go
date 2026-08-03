// Package scope parses and validates scan targets (CIDR ranges or single IP
// addresses) and estimates the number of addressable hosts in a target.
package scope

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// Target is a syntactically validated scan target: either a CIDR prefix or a
// single IP address.
type Target struct {
	raw    string
	addr   netip.Addr
	prefix netip.Prefix
	isCIDR bool
}

// Parse validates raw as a CIDR prefix (e.g. "192.168.1.0/24") or a single IP
// address (e.g. "192.168.1.45", IPv4 or IPv6). It returns an error for any
// other input. Surrounding whitespace is tolerated; addresses with a zone
// (e.g. "fe80::1%eth0") are rejected because they are not meaningful scan
// scopes.
func Parse(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, errors.New("scope: empty target: expected a CIDR range or IP address")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Target{}, fmt.Errorf("scope: invalid CIDR target %q: %v", raw, err)
		}
		if p.Addr().Zone() != "" {
			return Target{}, fmt.Errorf("scope: invalid CIDR target %q: zones are not allowed", raw)
		}
		return Target{raw: s, prefix: p, isCIDR: true}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return Target{}, fmt.Errorf("scope: invalid target %q: not a valid CIDR range or IP address", raw)
	}
	if a.Zone() != "" {
		return Target{}, fmt.Errorf("scope: invalid target %q: zones are not allowed", raw)
	}
	return Target{raw: s, addr: a}, nil
}

// String returns the target exactly as the operator supplied it (trimmed).
func (t Target) String() string { return t.raw }

// IsCIDR reports whether the target is a CIDR prefix rather than a single IP.
func (t Target) IsCIDR() bool { return t.isCIDR }

// HostCount estimates the number of addressable hosts in the target.
//
// A single IP yields 1. For a CIDR prefix the estimate is 2^(host bits); for
// IPv4 prefixes larger than two addresses the network and broadcast addresses
// are excluded (a /31 is a point-to-point link and keeps both addresses). The
// result is a *big.Int so IPv6 prefixes (e.g. a /64) cannot overflow.
func (t Target) HostCount() *big.Int {
	if !t.isCIDR {
		return big.NewInt(1)
	}
	p := t.prefix.Masked()
	hostBits := uint(p.Addr().BitLen() - p.Bits())
	n := new(big.Int).Lsh(big.NewInt(1), hostBits)
	if p.Addr().Is4() && n.Cmp(big.NewInt(2)) > 0 {
		n.Sub(n, big.NewInt(2))
	}
	return n
}
