// Package spf implements Sender Policy Framework (SPF) record parsing,
// validation, and evaluation per RFC 7208.
//
// SPF allows domain owners to specify which mail servers are authorized
// to send email on behalf of their domain via DNS TXT records.
package spf

import (
	"fmt"
	"net"
	"strings"
)

// Mechanism represents a single SPF mechanism (e.g., "ip4:192.168.1.0/24",
// "include:example.com", "a", "mx", "all").
type Mechanism struct {
	// Qualifier is the prefix character: '+', '-', '~', '?'.
	// Default is '+' (pass) when omitted.
	Qualifier rune

	// Type is the mechanism type: all, include, a, mx, ip4, ip6, exists, ptr, redirect.
	Type string

	// Value is the mechanism value (e.g., the IP address, domain, or CIDR).
	Value string

	// PrefixLen is the CIDR prefix length for ip4/ip6 mechanisms (0 if not specified).
	PrefixLen int

	// PrefixLen6 is the IPv6 CIDR prefix length for 'a' and 'mx' mechanisms.
	PrefixLen6 int
}

// String returns the string representation of a mechanism.
func (m Mechanism) String() string {
	var b strings.Builder
	b.WriteRune(m.Qualifier)
	b.WriteString(m.Type)
	if m.Value != "" {
		b.WriteByte(':')
		b.WriteString(m.Value)
	}
	if m.PrefixLen > 0 {
		fmt.Fprintf(&b, "/%d", m.PrefixLen)
	}
	if m.PrefixLen6 > 0 {
		fmt.Fprintf(&b, "//%d", m.PrefixLen6)
	}
	return b.String()
}

// Result is the outcome of an SPF evaluation.
type Result string

const (
	ResultPass      Result = "pass"
	ResultFail      Result = "fail"
	ResultSoftFail  Result = "softfail"
	ResultNeutral   Result = "neutral"
	ResultTempError Result = "temperror"
	ResultPermError Result = "permerror"
	ResultNone      Result = "none"
)

// Record represents a parsed SPF record.
type Record struct {
	// Version should always be "spf1".
	Version string

	// Mechanisms is the list of mechanisms in the record.
	Mechanisms []Mechanism

	// Redirect is the redirect target (empty if none).
	Redirect string

	// Explanation is the exp modifier target (empty if none).
	Explanation string

	// Other modifiers (e.g., "ra=..." for non-standard).
	Modifiers map[string]string

	// Raw is the original TXT record text.
	Raw string
}

// Parse parses an SPF record string into a Record.
// Returns an error if the record is not a valid SPF record.
func Parse(text string) (*Record, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty SPF record")
	}

	// SPF records may be split across multiple TXT strings; we receive
	// them already concatenated. The version must be at the start.
	if !strings.HasPrefix(strings.ToLower(text), "v=spf1") {
		return nil, fmt.Errorf("not an SPF record: missing v=spf1 prefix")
	}

	rec := &Record{
		Version:   "spf1",
		Modifiers: make(map[string]string),
		Raw:       text,
	}

	// Split into tokens (whitespace-separated).
	tokens := strings.Fields(text)
	// First token is v=spf1
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if err := rec.parseToken(tok); err != nil {
			return nil, fmt.Errorf("token %q: %w", tok, err)
		}
	}

	return rec, nil
}

// parseToken parses a single SPF token (mechanism or modifier).
func (r *Record) parseToken(token string) error {
	if token == "" {
		return nil
	}

	// Check for modifiers (contain '=' but not qualifier-prefixed mechanisms)
	// Modifiers: redirect=, exp=, and unknown name=value pairs.
	// Mechanisms: all, include:, a, mx, ip4:, ip6:, exists:, ptr, and qualified versions.

	// First, check if it's a modifier (name=value where name doesn't start with qualifier)
	if idx := strings.Index(token, "="); idx > 0 {
		name := token[:idx]
		value := token[idx+1:]

		// Check if name is a known modifier
		switch name {
		case "redirect":
			if r.Redirect != "" {
				return fmt.Errorf("duplicate redirect modifier")
			}
			r.Redirect = value
			return nil
		case "exp":
			if r.Explanation != "" {
				return fmt.Errorf("duplicate exp modifier")
			}
			r.Explanation = value
			return nil
		default:
			// Unknown modifier — store it. But first verify it's not a
			// mechanism with a qualifier (e.g., "+all" has no '=' so this is fine).
			// Unknown modifiers are allowed per RFC 7208 Section 4.6.3.
			if r.Modifiers == nil {
				r.Modifiers = make(map[string]string)
			}
			r.Modifiers[name] = value
			return nil
		}
	}

	// It's a mechanism. Parse qualifier.
	m := Mechanism{Qualifier: '+'}
	rest := token
	if len(token) > 0 && (token[0] == '+' || token[0] == '-' || token[0] == '~' || token[0] == '?') {
		m.Qualifier = rune(token[0])
		rest = token[1:]
	}

	// Parse mechanism type and value
	// Types with values: include:, a, mx, ip4:, ip6:, exists:, ptr
	// Types without values: all, a, mx, ptr (domain defaults to current domain)

	if rest == "all" {
		m.Type = "all"
		r.Mechanisms = append(r.Mechanisms, m)
		return nil
	}

	// Check for "type:value" — mechanisms use ':'
	if idx := strings.Index(rest, ":"); idx > 0 {
		m.Type = rest[:idx]
		m.Value = rest[idx+1:]
	} else {
		// Mechanism without value (a, mx, ptr) — may have CIDR
		// Check for CIDR notation (a/24, mx/24, a/24//64)
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			m.Type = rest[:slashIdx]
			cidrPart := rest[slashIdx:]
			// Parse CIDR from the cidr part
			if dslashIdx := strings.Index(cidrPart, "//"); dslashIdx >= 0 {
				// Dual CIDR: /24//64
				if dslashIdx > 1 {
					if _, err := fmt.Sscanf(cidrPart[:dslashIdx], "/%d", &m.PrefixLen); err != nil {
						return fmt.Errorf("invalid IPv4 CIDR prefix %q: %w", cidrPart[:dslashIdx], err)
					}
				}
				if _, err := fmt.Sscanf(cidrPart[dslashIdx+2:], "%d", &m.PrefixLen6); err != nil {
					return fmt.Errorf("invalid IPv6 CIDR prefix %q: %w", cidrPart[dslashIdx+2:], err)
				}
			} else {
				if _, err := fmt.Sscanf(cidrPart, "/%d", &m.PrefixLen); err != nil {
					return fmt.Errorf("invalid CIDR prefix %q: %w", cidrPart, err)
				}
			}
		} else {
			m.Type = rest
		}
	}

	// For ip4/ip6, the value may contain CIDR — extract it
	if m.Type == "ip4" || m.Type == "ip6" {
		if slashIdx := strings.Index(m.Value, "/"); slashIdx >= 0 {
			if _, err := fmt.Sscanf(m.Value[slashIdx+1:], "%d", &m.PrefixLen); err != nil {
				return fmt.Errorf("invalid CIDR prefix length %q: %w", m.Value[slashIdx+1:], err)
			}
			m.Value = m.Value[:slashIdx]
		}
	}

	// Validate mechanism type
	switch m.Type {
	case "include", "a", "mx", "ip4", "ip6", "exists", "ptr":
		// Valid types
	default:
		return fmt.Errorf("unknown mechanism type: %q", m.Type)
	}

	r.Mechanisms = append(r.Mechanisms, m)
	return nil
}

// Validate checks an SPF record for common configuration errors.
// Returns a list of issues found (empty if no issues).
func Validate(rec *Record) []string {
	var issues []string

	if rec == nil {
		return []string{"nil SPF record"}
	}

	// Check for "all" mechanism
	hasAll := false
	allIdx := -1
	for i, m := range rec.Mechanisms {
		if m.Type == "all" {
			hasAll = true
			allIdx = i
		}
	}

	if !hasAll {
		issues = append(issues, "no 'all' mechanism found — record may cause excessive DNS lookups")
	} else if allIdx != len(rec.Mechanisms)-1 {
		issues = append(issues, "'all' mechanism is not last — subsequent mechanisms will never be evaluated")
	}

	// Check for -all vs ~all
	if hasAll {
		allMech := rec.Mechanisms[allIdx]
		switch allMech.Qualifier {
		case '+':
			issues = append(issues, "'all' mechanism uses '+' (pass) — domain accepts email from any server (insecure)")
		case '?':
			issues = append(issues, "'all' mechanism uses '?' (neutral) — provides no protection")
		}
	}

	// Count DNS-lookup mechanisms (include, a, mx, ptr, exists, redirect)
	// RFC 7208 limits to 10 DNS queries.
	dnsLookups := 0
	for _, m := range rec.Mechanisms {
		switch m.Type {
		case "include", "a", "mx", "ptr", "exists":
			dnsLookups++
		}
	}
	if rec.Redirect != "" {
		dnsLookups++
	}
	if dnsLookups > 10 {
		issues = append(issues, fmt.Sprintf("exceeds DNS lookup limit (10): %d lookups required", dnsLookups))
	}

	// Check for ptr mechanism (deprecated per RFC 7208 Section 5.5)
	for _, m := range rec.Mechanisms {
		if m.Type == "ptr" {
			issues = append(issues, "'ptr' mechanism is deprecated and should not be used")
		}
	}

	// Check for redirect + all (redirect is ignored if all is present)
	if hasAll && rec.Redirect != "" {
		issues = append(issues, "'redirect' modifier is ignored when 'all' mechanism is present")
	}

	return issues
}

// EvaluateMechanism checks if an IP address matches a single SPF mechanism.
// Returns true if the IP matches the mechanism.
func EvaluateMechanism(m Mechanism, ip net.IP, domain string, resolver DNSResolver) (bool, error) {
	switch m.Type {
	case "all":
		return true, nil

	case "ip4":
		return matchIP4(m, ip)

	case "ip6":
		return matchIP6(m, ip)

	case "a":
		target := m.Value
		if target == "" {
			target = domain
		}
		return matchA(m, ip, target, resolver)

	case "mx":
		target := m.Value
		if target == "" {
			target = domain
		}
		return matchMX(m, ip, target, resolver)

	case "include":
		// Include requires recursive SPF evaluation — handled by Evaluate.
		return false, fmt.Errorf("include mechanism requires recursive evaluation")

	case "ptr":
		// Deprecated, but we implement it.
		return matchPTR(ip, domain, resolver)

	case "exists":
		return matchExists(m.Value, resolver)

	default:
		return false, fmt.Errorf("unknown mechanism type: %s", m.Type)
	}
}

// matchIP4 checks if an IP matches an ip4 mechanism.
func matchIP4(m Mechanism, ip net.IP) (bool, error) {
	parsedIP := ip.To4()
	if parsedIP == nil {
		return false, nil // Not an IPv4 address
	}

	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", m.Value, m.PrefixLen))
	if m.PrefixLen == 0 {
		_, network, err = net.ParseCIDR(m.Value + "/32")
	}
	if err != nil {
		return false, fmt.Errorf("invalid ip4 address %q: %w", m.Value, err)
	}

	return network.Contains(parsedIP), nil
}

// matchIP6 checks if an IP matches an ip6 mechanism.
func matchIP6(m Mechanism, ip net.IP) (bool, error) {
	parsedIP := ip.To16()
	if parsedIP == nil {
		return false, nil
	}
	// Ensure it's actually IPv6
	if ip.To4() != nil {
		return false, nil
	}

	cidr := fmt.Sprintf("%s/%d", m.Value, m.PrefixLen)
	if m.PrefixLen == 0 {
		cidr = m.Value + "/128"
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid ip6 address %q: %w", m.Value, err)
	}

	return network.Contains(parsedIP), nil
}

// matchA checks if an IP matches the 'a' mechanism (resolves A/AAAA records).
func matchA(m Mechanism, ip net.IP, target string, resolver DNSResolver) (bool, error) {
	ips, err := resolver.LookupIP(target)
	if err != nil {
		return false, nil // DNS error → no match (treated as no match, not error in SPF)
	}

	for _, resolved := range ips {
		if ip.Equal(resolved) {
			return true, nil
		}
		// Check CIDR
		if m.PrefixLen > 0 && ip.To4() != nil && resolved.To4() != nil {
			_, network, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", resolved.String(), m.PrefixLen))
			if network.Contains(ip) {
				return true, nil
			}
		}
	}
	return false, nil
}

// matchMX checks if an IP matches the 'mx' mechanism (resolves MX records).
func matchMX(m Mechanism, ip net.IP, target string, resolver DNSResolver) (bool, error) {
	mxs, err := resolver.LookupMX(target)
	if err != nil {
		return false, nil
	}

	for _, mx := range mxs {
		ips, err := resolver.LookupIP(mx.Host)
		if err != nil {
			continue
		}
		for _, resolved := range ips {
			if ip.Equal(resolved) {
				return true, nil
			}
			if m.PrefixLen > 0 && ip.To4() != nil && resolved.To4() != nil {
				_, network, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", resolved.String(), m.PrefixLen))
				if network.Contains(ip) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// matchPTR checks if an IP matches the 'ptr' mechanism (deprecated).
func matchPTR(ip net.IP, domain string, resolver DNSResolver) (bool, error) {
	names, err := resolver.LookupPTR(ip.String())
	if err != nil || len(names) == 0 {
		return false, nil
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true, nil
		}
	}
	return false, nil
}

// matchExists checks if the 'exists' mechanism matches (DNS A query succeeds).
func matchExists(target string, resolver DNSResolver) (bool, error) {
	ips, err := resolver.LookupIP(target)
	if err != nil {
		return false, nil
	}
	return len(ips) > 0, nil
}

// Evaluate evaluates an SPF record against a given IP and domain.
// Returns the SPF result and the matching mechanism (if any).
func Evaluate(rec *Record, ip net.IP, domain string, resolver DNSResolver) (Result, Mechanism, error) {
	if rec == nil {
		return ResultNone, Mechanism{}, nil
	}

	for _, m := range rec.Mechanisms {
		if m.Type == "include" {
			// Recursive evaluation
			target := m.Value
			if target == "" {
				target = domain
			}
			subRec, err := resolver.LookupSPF(target)
			if err != nil {
				return ResultTempError, m, fmt.Errorf("include lookup failed: %w", err)
			}
			result, _, err := Evaluate(subRec, ip, target, resolver)
			if err != nil {
				return result, m, err
			}
			if result == ResultPass {
				return qualifierToResult(m.Qualifier), m, nil
			}
			if result == ResultTempError {
				return ResultTempError, m, nil
			}
			if result == ResultPermError {
				return ResultPermError, m, nil
			}
			continue
		}

		matched, err := EvaluateMechanism(m, ip, domain, resolver)
		if err != nil {
			return ResultPermError, m, err
		}
		if matched {
			return qualifierToResult(m.Qualifier), m, nil
		}
	}

	// Check redirect
	if rec.Redirect != "" {
		redirectRec, err := resolver.LookupSPF(rec.Redirect)
		if err != nil {
			return ResultTempError, Mechanism{}, fmt.Errorf("redirect lookup failed: %w", err)
		}
		return Evaluate(redirectRec, ip, rec.Redirect, resolver)
	}

	return ResultNeutral, Mechanism{}, nil
}

// qualifierToResult converts a qualifier rune to an SPF result.
func qualifierToResult(q rune) Result {
	switch q {
	case '+':
		return ResultPass
	case '-':
		return ResultFail
	case '~':
		return ResultSoftFail
	case '?':
		return ResultNeutral
	default:
		return ResultPass
	}
}

// DNSResolver is the interface for DNS operations used by SPF evaluation.
type DNSResolver interface {
	LookupIP(domain string) ([]net.IP, error)
	LookupMX(domain string) ([]*net.MX, error)
	LookupPTR(ip string) ([]string, error)
	LookupSPF(domain string) (*Record, error)
	LookupTXT(domain string) ([]string, error)
}
