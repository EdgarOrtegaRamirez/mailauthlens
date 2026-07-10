// Package dmarc implements DMARC (Domain-based Message Authentication,
// Reporting, and Conformance) record parsing, validation, and policy
// evaluation per RFC 9989 (DMARCbis, obsoleting RFC 7489).
//
// DMARC allows domain owners to publish email authentication policies
// via DNS TXT records that specify how receivers should handle
// messages that fail SPF and/or DKIM alignment checks.
package dmarc

import (
	"fmt"
	"strings"
)

// Policy represents a DMARC policy action.
type Policy string

const (
	PolicyNone       Policy = "none"
	PolicyQuarantine Policy = "quarantine"
	PolicyReject     Policy = "reject"
)

// AlignmentMode represents the identifier alignment strictness.
type AlignmentMode string

const (
	AlignmentRelaxed AlignmentMode = "r" // relaxed
	AlignmentStrict  AlignmentMode = "s" // strict
)

// PSDFlag represents the psd= tag value (Public Suffix Domain flag).
type PSDFlag string

const (
	PSDYes     PSDFlag = "y" // domain is a PSD
	PSDNo      PSDFlag = "n" // domain is not a PSD, is org domain
	PSDUnknown PSDFlag = "u" // default — may or may not be PSD
)

// Record represents a parsed DMARC record per RFC 9989.
type Record struct {
	// Version (v= tag). Should be "DMARC1".
	Version string

	// Policy (p= tag). The domain-level policy.
	Policy Policy

	// SubdomainPolicy (sp= tag). The subdomain policy (defaults to p=).
	SubdomainPolicy Policy

	// AlignmentDKIM (adkim= tag). DKIM alignment mode (defaults to relaxed).
	AlignmentDKIM AlignmentMode

	// AlignmentSPF (aspf= tag). SPF alignment mode (defaults to relaxed).
	AlignmentSPF AlignmentMode

	// AggregateReportURIs (rua= tag). URIs for aggregate reports.
	AggregateReportURIs []string

	// FailureReportURIs (ruf= tag). URIs for failure reports.
	FailureReportURIs []string

	// FailureOptions (fo= tag). Failure reporting options.
	FailureOptions string

	// ReportingInterval (ri= tag). Report interval in seconds.
	ReportingInterval int64

	// PSD (psd= tag). Public Suffix Domain flag (RFC 9989 addition).
	PSD PSDFlag

	// NPDomainPolicy (np= tag). Non-existent subdomain policy (RFC 9989 addition).
	NPDomainPolicy Policy

	// HasSubdomainPolicy indicates if sp= was explicitly set.
	HasSubdomainPolicy bool

	// HasNPDomainPolicy indicates if np= was explicitly set.
	HasNPDomainPolicy bool

	// HasPSD indicates if psd= was explicitly set.
	HasPSD bool

	// Raw is the original TXT record text.
	Raw string
}

// Parse parses a DMARC TXT record into a Record.
func Parse(text string) (*Record, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty DMARC record")
	}

	// DMARC records may be split across multiple TXT strings.
	// The version must be at the start.
	if !strings.HasPrefix(strings.ToLower(text), "v=dmarc1") {
		return nil, fmt.Errorf("not a DMARC record: missing v=DMARC1 prefix")
	}

	rec := &Record{
		Version:           "DMARC1",
		Policy:            PolicyNone,
		SubdomainPolicy:   PolicyNone,
		AlignmentDKIM:     AlignmentRelaxed,
		AlignmentSPF:      AlignmentRelaxed,
		PSD:               PSDUnknown,
		ReportingInterval: 86400,
		Raw:               text,
	}

	// Split into tokens (whitespace-separated).
	tokens := strings.Fields(text)
	// First token is v=DMARC1
	for i := 1; i < len(tokens); i++ {
		tok := strings.TrimSuffix(tokens[i], ";")
		if tok == "" {
			continue
		}
		if err := rec.parseToken(tok); err != nil {
			return nil, fmt.Errorf("token %q: %w", tok, err)
		}
	}

	return rec, nil
}

// parseToken parses a single DMARC tag=value pair.
func (r *Record) parseToken(token string) error {
	if token == "" {
		return nil
	}

	idx := strings.Index(token, "=")
	if idx < 0 {
		return fmt.Errorf("malformed token (no '='): %q", token)
	}

	name := strings.ToLower(token[:idx])
	value := token[idx+1:]

	switch name {
	case "p":
		p, err := parsePolicy(value)
		if err != nil {
			return err
		}
		r.Policy = p

	case "sp":
		p, err := parsePolicy(value)
		if err != nil {
			return err
		}
		r.SubdomainPolicy = p
		r.HasSubdomainPolicy = true

	case "np":
		// RFC 9989 addition: policy for non-existent subdomains
		p, err := parsePolicy(value)
		if err != nil {
			return err
		}
		r.NPDomainPolicy = p
		r.HasNPDomainPolicy = true

	case "adkim":
		mode, err := parseAlignmentMode(value)
		if err != nil {
			return err
		}
		r.AlignmentDKIM = mode

	case "aspf":
		mode, err := parseAlignmentMode(value)
		if err != nil {
			return err
		}
		r.AlignmentSPF = mode

	case "rua":
		r.AggregateReportURIs = parseURIList(value)

	case "ruf":
		r.FailureReportURIs = parseURIList(value)

	case "fo":
		r.FailureOptions = value

	case "ri":
		var n int64
		if _, err := fmt.Sscanf(value, "%d", &n); err == nil {
			r.ReportingInterval = n
		}

	case "psd":
		// RFC 9989 addition: Public Suffix Domain flag
		switch value {
		case "y", "n", "u":
			r.PSD = PSDFlag(value)
			r.HasPSD = true
		default:
			return fmt.Errorf("invalid psd= value: %q (must be y, n, or u)", value)
		}

	case "t":
		// Some older implementations use t= for testing; RFC 9989 removed it
		// but we accept it gracefully
		// (no-op, just don't error)

	default:
		// Unknown tag — RFC 9989 allows unknown tags (they should be ignored)
	}

	return nil
}

// parsePolicy parses a policy value.
func parsePolicy(value string) (Policy, error) {
	switch strings.ToLower(value) {
	case "none":
		return PolicyNone, nil
	case "quarantine":
		return PolicyQuarantine, nil
	case "reject":
		return PolicyReject, nil
	default:
		return "", fmt.Errorf("invalid policy value: %q (must be none, quarantine, or reject)", value)
	}
}

// parseAlignmentMode parses an alignment mode value.
func parseAlignmentMode(value string) (AlignmentMode, error) {
	switch strings.ToLower(value) {
	case "r", "relaxed":
		return AlignmentRelaxed, nil
	case "s", "strict":
		return AlignmentStrict, nil
	default:
		return "", fmt.Errorf("invalid alignment mode: %q (must be r or s)", value)
	}
}

// parseURIList parses a comma-separated list of URIs.
func parseURIList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var uris []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			uris = append(uris, p)
		}
	}
	return uris
}

// Validate checks a DMARC record for common configuration issues.
// Returns a list of issues found (empty if no issues).
func Validate(rec *Record) []string {
	var issues []string

	if rec == nil {
		return []string{"nil DMARC record"}
	}

	// Check policy strength
	if rec.Policy == PolicyNone {
		issues = append(issues, "policy is 'none' — provides monitoring only, no enforcement")
	}

	// Check if rua is missing (no aggregate reports)
	if len(rec.AggregateReportURIs) == 0 {
		issues = append(issues, "no rua= (aggregate report URI) set — cannot receive DMARC reports")
	}

	// Check if ruf is missing (no failure reports)
	if len(rec.FailureReportURIs) == 0 {
		issues = append(issues, "no ruf= (failure report URI) set — cannot receive per-message failure reports")
	}

	// Check for strict alignment (may cause false failures)
	if rec.AlignmentDKIM == AlignmentStrict {
		issues = append(issues, "DKIM alignment is strict — may cause legitimate mail to fail if sent via forwarding services")
	}
	if rec.AlignmentSPF == AlignmentStrict {
		issues = append(issues, "SPF alignment is strict — may cause legitimate mail to fail if sent via forwarding services")
	}

	// Check subdomain policy
	if rec.HasSubdomainPolicy && rec.SubdomainPolicy == PolicyNone && rec.Policy != PolicyNone {
		issues = append(issues, "subdomain policy (sp=) is 'none' while domain policy is stricter — subdomains are unprotected")
	}

	// Check for p=reject without rua (can't monitor)
	if rec.Policy == PolicyReject && len(rec.AggregateReportURIs) == 0 {
		issues = append(issues, "p=reject without rua= — cannot monitor impact of rejection policy")
	}

	// Check report URI external domain (simplified check)
	for _, uri := range rec.AggregateReportURIs {
		if strings.HasPrefix(uri, "mailto:") {
			email := strings.TrimPrefix(uri, "mailto:")
			// Check if the report URI domain differs from the policy domain
			// (this requires knowing the domain — done at a higher level)
			_ = email
		}
	}

	// Check for np= without psd=y (np= is only meaningful for PSDs per RFC 9989)
	if rec.HasNPDomainPolicy && rec.HasPSD && rec.PSD != PSDYes {
		issues = append(issues, "np= (non-existent subdomain policy) is set but psd= is not 'y' — np= is only meaningful for PSDs")
	}

	return issues
}

// AlignmentResult represents the result of identifier alignment checking.
type AlignmentResult struct {
	// Aligned is true if the identifier is aligned.
	Aligned bool

	// Mode is the alignment mode used.
	Mode AlignmentMode

	// AuthDomain is the authenticated domain (from SPF or DKIM).
	AuthDomain string

	// AuthorDomain is the RFC5322.From domain.
	AuthorDomain string

	// Reason explains the alignment result.
	Reason string
}

// CheckAlignment checks if an authenticated domain is aligned with the
// author domain according to the specified alignment mode.
//
// In relaxed mode, the Organizational Domains must match.
// In strict mode, the exact domains must match.
func CheckAlignment(authDomain, authorDomain string, mode AlignmentMode, orgDomain func(string) string) AlignmentResult {
	result := AlignmentResult{
		Mode:         mode,
		AuthDomain:   authDomain,
		AuthorDomain: authorDomain,
	}

	if authDomain == "" || authorDomain == "" {
		result.Reason = "empty domain"
		return result
	}

	authDomain = strings.ToLower(strings.TrimSuffix(authDomain, "."))
	authorDomain = strings.ToLower(strings.TrimSuffix(authorDomain, "."))

	switch mode {
	case AlignmentStrict:
		if authDomain == authorDomain {
			result.Aligned = true
			result.Reason = "exact domain match (strict)"
		} else {
			result.Reason = "domains do not match exactly (strict mode)"
		}

	case AlignmentRelaxed:
		authOrg := orgDomain(authDomain)
		authorOrg := orgDomain(authorDomain)
		if authOrg == authorOrg && authOrg != "" {
			result.Aligned = true
			result.Reason = fmt.Sprintf("organizational domains match (relaxed): %s", authOrg)
		} else {
			result.Reason = fmt.Sprintf("organizational domains differ: %s vs %s", authOrg, authorOrg)
		}
	}

	return result
}

// EvalResult represents the outcome of a DMARC evaluation.
type EvalResult struct {
	// Result is the DMARC evaluation result.
	Result string // "pass", "fail"

	// Policy is the applicable policy.
	Policy Policy

	// SPFAlignment is the SPF alignment check result.
	SPFAlignment AlignmentResult

	// DKIMAlignment is the DKIM alignment check result.
	DKIMAlignment AlignmentResult

	// SPFResult is the raw SPF result.
	SPFResult string

	// DKIMResult is the raw DKIM result.
	DKIMResult string

	// AuthorDomain is the RFC5322.From domain.
	AuthorDomain string

	// Reason explains the evaluation result.
	Reason string
}

// Evaluate performs a DMARC evaluation given SPF and DKIM results.
//
// Parameters:
//   - record: The DMARC record for the author domain
//   - authorDomain: The RFC5322.From domain
//   - spfResult: The SPF evaluation result ("pass", "fail", etc.)
//   - spfDomain: The domain that passed SPF (the MAIL FROM or HELO domain)
//   - dkimResult: The DKIM evaluation result ("pass", "fail", etc.)
//   - dkimDomain: The DKIM signing domain (d= tag)
//   - orgDomain: A function that returns the organizational domain for a given domain
func Evaluate(
	record *Record,
	authorDomain string,
	spfResult, spfDomain string,
	dkimResult, dkimDomain string,
	orgDomain func(string) string,
) EvalResult {
	result := EvalResult{
		AuthorDomain: authorDomain,
		SPFResult:    spfResult,
		DKIMResult:   dkimResult,
	}

	if record == nil {
		result.Result = "fail"
		result.Reason = "no DMARC record found"
		result.Policy = PolicyNone
		return result
	}

	result.Policy = record.Policy

	// Check DKIM alignment
	dkimAligned := false
	if dkimResult == "pass" && dkimDomain != "" {
		result.DKIMAlignment = CheckAlignment(dkimDomain, authorDomain, record.AlignmentDKIM, orgDomain)
		dkimAligned = result.DKIMAlignment.Aligned
	}

	// Check SPF alignment
	spfAligned := false
	if spfResult == "pass" && spfDomain != "" {
		result.SPFAlignment = CheckAlignment(spfDomain, authorDomain, record.AlignmentSPF, orgDomain)
		spfAligned = result.SPFAlignment.Aligned
	}

	// DMARC passes if either SPF or DKIM is aligned
	if dkimAligned || spfAligned {
		result.Result = "pass"
		if dkimAligned && spfAligned {
			result.Reason = "both SPF and DKIM aligned"
		} else if dkimAligned {
			result.Reason = "DKIM aligned"
		} else {
			result.Reason = "SPF aligned"
		}
	} else {
		result.Result = "fail"
		if dkimResult != "pass" && spfResult != "pass" {
			result.Reason = "neither SPF nor DKIM passed"
		} else if dkimResult == "pass" && spfResult == "pass" {
			result.Reason = "both SPF and DKIM passed but neither aligned"
		} else if dkimResult == "pass" {
			result.Reason = "DKIM passed but not aligned"
		} else {
			result.Reason = "SPF passed but not aligned"
		}
	}

	return result
}

// DNSQueryName returns the DNS query name for a DMARC record.
func DNSQueryName(domain string) string {
	return "_dmarc." + domain
}

// PolicyAction returns the action a receiver should take based on the
// DMARC result and policy.
func PolicyAction(result EvalResult) string {
	if result.Result == "pass" {
		return "deliver"
	}

	// Determine which policy applies (domain vs subdomain)
	policy := result.Policy
	// In a full implementation, we'd check if the author domain is a
	// subdomain of the policy domain and use sp= or np= accordingly.

	switch policy {
	case PolicyNone:
		return "deliver (monitor only)"
	case PolicyQuarantine:
		return "quarantine (spam folder / mark as spam)"
	case PolicyReject:
		return "reject (bounce message)"
	default:
		return "deliver (unknown policy)"
	}
}
