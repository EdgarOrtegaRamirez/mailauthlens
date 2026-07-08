// Package report provides report generation for email authentication
// analysis results in multiple formats (text, JSON, markdown).
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dmarc"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dkim"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dkim2"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dnslookup"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/spf"
)

// Format is the output format for reports.
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// DomainReport is a comprehensive report of a domain's email authentication
// configuration.
type DomainReport struct {
	Domain      string                 `json:"domain"`
	Timestamp   string                 `json:"timestamp"`
	SPF         *SPFReport             `json:"spf,omitempty"`
	DKIM        *DKIMReport             `json:"dkim,omitempty"`
	DKIM2       *DKIM2Report            `json:"dkim2,omitempty"`
	DMARC       *DMARCReport            `json:"dmarc,omitempty"`
	MXRecords   []string               `json:"mx_records,omitempty"`
	MTASTS      string                  `json:"mta_sts,omitempty"`
	TLSRPT      string                  `json:"tls_rpt,omitempty"`
	DomainCheck *dnslookup.DomainCheck `json:"domain_check,omitempty"`
	Score       int                     `json:"score"`
	Grade       string                  `json:"grade"`
	Issues       []string               `json:"issues,omitempty"`
}

// SPFReport contains SPF analysis results.
type SPFReport struct {
	Record  string         `json:"record"`
	Parsed  *spf.Record    `json:"parsed,omitempty"`
	Issues  []string       `json:"issues,omitempty"`
	Found   bool           `json:"found"`
}

// DKIMReport contains DKIM analysis results for a specific selector.
type DKIMReport struct {
	Selector string          `json:"selector"`
	Record   string          `json:"record"`
	Parsed   *dkim.KeyRecord `json:"parsed,omitempty"`
	Issues   []string        `json:"issues,omitempty"`
	Found    bool            `json:"found"`
}

// DKIM2Report contains DKIM2 analysis results.
type DKIM2Report struct {
	Selector string            `json:"selector"`
	Record   string            `json:"record"`
	Parsed   *dkim2.KeyRecord  `json:"parsed,omitempty"`
	Issues   []string          `json:"issues,omitempty"`
	Found    bool              `json:"found"`
}

// DMARCReport contains DMARC analysis results.
type DMARCReport struct {
	Record  string        `json:"record"`
	Parsed  *dmarc.Record `json:"parsed,omitempty"`
	Issues  []string      `json:"issues,omitempty"`
	Found   bool          `json:"found"`
}

// GenerateDomainReport creates a comprehensive report for a domain.
func GenerateDomainReport(
	domain string,
	resolver *dnslookup.Resolver,
	dkimSelectors []string,
	dkim2Selectors []string,
) *DomainReport {
	report := &DomainReport{
		Domain:    domain,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Issues:    []string{},
	}

	// Check domain
	report.DomainCheck = resolver.CheckDomain(domain)

	// SPF
	if report.DomainCheck.SPFError == "" {
		if spfRec, err := spf.Parse(report.DomainCheck.SPFRecord); err == nil {
			issues := spf.Validate(spfRec)
			report.SPF = &SPFReport{
				Record: spfRec.Raw,
				Parsed: spfRec,
				Issues: issues,
				Found:  true,
			}
			report.Issues = append(report.Issues, issues...)
		}
	} else {
		report.SPF = &SPFReport{Found: false}
		report.Issues = append(report.Issues, "SPF: "+report.DomainCheck.SPFError)
	}

	// DMARC
	if report.DomainCheck.DMARCError == "" {
		if dmarcRec, err := dmarc.Parse(report.DomainCheck.DMARCRecord); err == nil {
			issues := dmarc.Validate(dmarcRec)
			report.DMARC = &DMARCReport{
				Record: dmarcRec.Raw,
				Parsed: dmarcRec,
				Issues: issues,
				Found:  true,
			}
			report.Issues = append(report.Issues, issues...)
		}
	} else {
		report.DMARC = &DMARCReport{Found: false}
		report.Issues = append(report.Issues, "DMARC: "+report.DomainCheck.DMARCError)
	}

	// DKIM selectors
	for _, selector := range dkimSelectors {
		record, err := resolver.LookupDKIMKey(selector, domain)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("DKIM selector %s: %v", selector, err))
			continue
		}
		keyRec, err := dkim.ParseKeyRecord(record)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("DKIM selector %s: %v", selector, err))
			continue
		}
		issues := dkim.Validate(nil, keyRec)
		report.DKIM = &DKIMReport{
			Selector: selector,
			Record:   record,
			Parsed:   keyRec,
			Issues:   issues,
			Found:    true,
		}
		report.Issues = append(report.Issues, issues...)
	}

	// DKIM2 selectors
	for _, selector := range dkim2Selectors {
		record, err := resolver.LookupDKIM2Key(selector, domain)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("DKIM2 selector %s: %v", selector, err))
			continue
		}
		keyRec, err := dkim2.ParseKeyRecord(record)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("DKIM2 selector %s: %v", selector, err))
			continue
		}
		issues := dkim2.Validate(nil, keyRec)
		report.DKIM2 = &DKIM2Report{
			Selector: selector,
			Record:   record,
			Parsed:   keyRec,
			Issues:   issues,
			Found:    true,
		}
		report.Issues = append(report.Issues, issues...)
	}

	// MX records
	report.MXRecords = report.DomainCheck.MXRecords

	// MTA-STS
	report.MTASTS = report.DomainCheck.MTASTS

	// TLS-RPT
	report.TLSRPT = report.DomainCheck.TLSRPT

	// Calculate score
	report.Score, report.Grade = calculateScore(report)

	return report
}

// calculateScore computes a 0-100 security score based on the report.
func calculateScore(report *DomainReport) (int, string) {
	score := 0

	// SPF (20 points)
	if report.SPF != nil && report.SPF.Found {
		score += 10
		if len(report.SPF.Issues) == 0 {
			score += 10
		}
	}

	// DMARC (30 points)
	if report.DMARC != nil && report.DMARC.Found {
		score += 10
		if report.DMARC.Parsed != nil {
			switch report.DMARC.Parsed.Policy {
			case dmarc.PolicyQuarantine:
				score += 10
			case dmarc.PolicyReject:
				score += 20
			case dmarc.PolicyNone:
				score += 5
			}
		}
		if len(report.DMARC.Issues) == 0 {
			score += 5
		}
	}

	// DKIM (20 points)
	if report.DKIM != nil && report.DKIM.Found {
		score += 10
		if len(report.DKIM.Issues) == 0 {
			score += 10
		}
	}

	// DKIM2 (10 points)
	if report.DKIM2 != nil && report.DKIM2.Found {
		score += 10
	}

	// MX records (5 points)
	if len(report.MXRecords) > 0 {
		score += 5
	}

	// MTA-STS (10 points)
	if report.MTASTS != "" {
		score += 5
	}

	// TLS-RPT (5 points)
	if report.TLSRPT != "" {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	// Grade
	var grade string
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	default:
		grade = "F"
	}

	return score, grade
}

// FormatReport formats a DomainReport in the specified format.
func FormatReport(report *DomainReport, format Format) (string, error) {
	switch format {
	case FormatJSON:
		return formatJSON(report)
	case FormatMarkdown:
		return formatMarkdown(report), nil
	default:
		return formatText(report), nil
	}
}

func formatJSON(report *DomainReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	return string(data), nil
}

func formatText(report *DomainReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "MailAuthLens Report for %s\n", report.Domain)
	fmt.Fprintf(&b, "Generated: %s\n\n", report.Timestamp)

	fmt.Fprintf(&b, "Security Score: %d/100 (Grade: %s)\n\n", report.Score, report.Grade)

	// SPF
	fmt.Fprintf(&b, "=== SPF ===\n")
	if report.SPF != nil && report.SPF.Found {
		fmt.Fprintf(&b, "  Record: %s\n", report.SPF.Record)
		if len(report.SPF.Issues) > 0 {
			fmt.Fprintf(&b, "  Issues:\n")
			for _, issue := range report.SPF.Issues {
				fmt.Fprintf(&b, "    - %s\n", issue)
			}
		} else {
			fmt.Fprintf(&b, "  No issues found.\n")
		}
	} else {
		fmt.Fprintf(&b, "  No SPF record found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// DMARC
	fmt.Fprintf(&b, "=== DMARC (RFC 9989) ===\n")
	if report.DMARC != nil && report.DMARC.Found {
		fmt.Fprintf(&b, "  Record: %s\n", report.DMARC.Record)
		if report.DMARC.Parsed != nil {
			fmt.Fprintf(&b, "  Policy: %s\n", report.DMARC.Parsed.Policy)
			if report.DMARC.Parsed.HasSubdomainPolicy {
				fmt.Fprintf(&b, "  Subdomain Policy: %s\n", report.DMARC.Parsed.SubdomainPolicy)
			}
			fmt.Fprintf(&b, "  DKIM Alignment: %s\n", report.DMARC.Parsed.AlignmentDKIM)
			fmt.Fprintf(&b, "  SPF Alignment: %s\n", report.DMARC.Parsed.AlignmentSPF)
			if report.DMARC.Parsed.HasPSD {
				fmt.Fprintf(&b, "  PSD Flag: %s\n", report.DMARC.Parsed.PSD)
			}
			if report.DMARC.Parsed.HasNPDomainPolicy {
				fmt.Fprintf(&b, "  NP Policy: %s\n", report.DMARC.Parsed.NPDomainPolicy)
			}
		}
		if len(report.DMARC.Issues) > 0 {
			fmt.Fprintf(&b, "  Issues:\n")
			for _, issue := range report.DMARC.Issues {
				fmt.Fprintf(&b, "    - %s\n", issue)
			}
		} else {
			fmt.Fprintf(&b, "  No issues found.\n")
		}
	} else {
		fmt.Fprintf(&b, "  No DMARC record found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// DKIM
	fmt.Fprintf(&b, "=== DKIM ===\n")
	if report.DKIM != nil && report.DKIM.Found {
		fmt.Fprintf(&b, "  Selector: %s\n", report.DKIM.Selector)
		fmt.Fprintf(&b, "  Record: %s\n", report.DKIM.Record)
		if len(report.DKIM.Issues) > 0 {
			fmt.Fprintf(&b, "  Issues:\n")
			for _, issue := range report.DKIM.Issues {
				fmt.Fprintf(&b, "    - %s\n", issue)
			}
		} else {
			fmt.Fprintf(&b, "  No issues found.\n")
		}
	} else {
		fmt.Fprintf(&b, "  No DKIM key found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// DKIM2
	fmt.Fprintf(&b, "=== DKIM2 (draft-ietf-dkim-dkim2-spec) ===\n")
	if report.DKIM2 != nil && report.DKIM2.Found {
		fmt.Fprintf(&b, "  Selector: %s\n", report.DKIM2.Selector)
		fmt.Fprintf(&b, "  Record: %s\n", report.DKIM2.Record)
		if len(report.DKIM2.Issues) > 0 {
			fmt.Fprintf(&b, "  Issues:\n")
			for _, issue := range report.DKIM2.Issues {
				fmt.Fprintf(&b, "    - %s\n", issue)
			}
		} else {
			fmt.Fprintf(&b, "  No issues found.\n")
		}
	} else {
		fmt.Fprintf(&b, "  No DKIM2 key found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// MX Records
	fmt.Fprintf(&b, "=== MX Records ===\n")
	if len(report.MXRecords) > 0 {
		for _, mx := range report.MXRecords {
			fmt.Fprintf(&b, "  %s\n", mx)
		}
	} else {
		fmt.Fprintf(&b, "  No MX records found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// MTA-STS
	fmt.Fprintf(&b, "=== MTA-STS ===\n")
	if report.MTASTS != "" {
		fmt.Fprintf(&b, "  Record: %s\n", report.MTASTS)
	} else {
		fmt.Fprintf(&b, "  No MTA-STS record found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// TLS-RPT
	fmt.Fprintf(&b, "=== TLS-RPT ===\n")
	if report.TLSRPT != "" {
		fmt.Fprintf(&b, "  Record: %s\n", report.TLSRPT)
	} else {
		fmt.Fprintf(&b, "  No TLS-RPT record found.\n")
	}
	fmt.Fprintf(&b, "\n")

	// All Issues
	if len(report.Issues) > 0 {
		fmt.Fprintf(&b, "=== All Issues (%d) ===\n", len(report.Issues))
		for _, issue := range report.Issues {
			fmt.Fprintf(&b, "  - %s\n", issue)
		}
	}

	return b.String()
}

func formatMarkdown(report *DomainReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# MailAuthLens Report: %s\n\n", report.Domain)
	fmt.Fprintf(&b, "Generated: %s\n\n", report.Timestamp)
	fmt.Fprintf(&b, "## Security Score: %d/100 (Grade: %s)\n\n", report.Score, report.Grade)

	// SPF
	fmt.Fprintf(&b, "## SPF\n\n")
	if report.SPF != nil && report.SPF.Found {
		fmt.Fprintf(&b, "**Record:** `%s`\n\n", report.SPF.Record)
		if len(report.SPF.Issues) > 0 {
			fmt.Fprintf(&b, "**Issues:**\n\n")
			for _, issue := range report.SPF.Issues {
				fmt.Fprintf(&b, "- %s\n", issue)
			}
			fmt.Fprintf(&b, "\n")
		} else {
			fmt.Fprintf(&b, "✅ No issues found.\n\n")
		}
	} else {
		fmt.Fprintf(&b, "❌ No SPF record found.\n\n")
	}

	// DMARC
	fmt.Fprintf(&b, "## DMARC (RFC 9989)\n\n")
	if report.DMARC != nil && report.DMARC.Found {
		fmt.Fprintf(&b, "**Record:** `%s`\n\n", report.DMARC.Record)
		if report.DMARC.Parsed != nil {
			fmt.Fprintf(&b, "| Tag | Value |\n|-----|-------|\n")
			fmt.Fprintf(&b, "| Policy (p=) | %s |\n", report.DMARC.Parsed.Policy)
			if report.DMARC.Parsed.HasSubdomainPolicy {
				fmt.Fprintf(&b, "| Subdomain Policy (sp=) | %s |\n", report.DMARC.Parsed.SubdomainPolicy)
			}
			fmt.Fprintf(&b, "| DKIM Alignment (adkim=) | %s |\n", report.DMARC.Parsed.AlignmentDKIM)
			fmt.Fprintf(&b, "| SPF Alignment (aspf=) | %s |\n", report.DMARC.Parsed.AlignmentSPF)
			if report.DMARC.Parsed.HasPSD {
				fmt.Fprintf(&b, "| PSD Flag (psd=) | %s |\n", report.DMARC.Parsed.PSD)
			}
			if report.DMARC.Parsed.HasNPDomainPolicy {
				fmt.Fprintf(&b, "| NP Policy (np=) | %s |\n", report.DMARC.Parsed.NPDomainPolicy)
			}
			fmt.Fprintf(&b, "\n")
		}
		if len(report.DMARC.Issues) > 0 {
			fmt.Fprintf(&b, "**Issues:**\n\n")
			for _, issue := range report.DMARC.Issues {
				fmt.Fprintf(&b, "- %s\n", issue)
			}
			fmt.Fprintf(&b, "\n")
		} else {
			fmt.Fprintf(&b, "✅ No issues found.\n\n")
		}
	} else {
		fmt.Fprintf(&b, "❌ No DMARC record found.\n\n")
	}

	// DKIM
	fmt.Fprintf(&b, "## DKIM\n\n")
	if report.DKIM != nil && report.DKIM.Found {
		fmt.Fprintf(&b, "**Selector:** `%s`\n\n", report.DKIM.Selector)
		fmt.Fprintf(&b, "**Record:** `%s`\n\n", report.DKIM.Record)
		if len(report.DKIM.Issues) > 0 {
			fmt.Fprintf(&b, "**Issues:**\n\n")
			for _, issue := range report.DKIM.Issues {
				fmt.Fprintf(&b, "- %s\n", issue)
			}
			fmt.Fprintf(&b, "\n")
		} else {
			fmt.Fprintf(&b, "✅ No issues found.\n\n")
		}
	} else {
		fmt.Fprintf(&b, "❌ No DKIM key found.\n\n")
	}

	// DKIM2
	fmt.Fprintf(&b, "## DKIM2 (draft-ietf-dkim-dkim2-spec)\n\n")
	if report.DKIM2 != nil && report.DKIM2.Found {
		fmt.Fprintf(&b, "**Selector:** `%s`\n\n", report.DKIM2.Selector)
		fmt.Fprintf(&b, "**Record:** `%s`\n\n", report.DKIM2.Record)
		if len(report.DKIM2.Issues) > 0 {
			fmt.Fprintf(&b, "**Issues:**\n\n")
			for _, issue := range report.DKIM2.Issues {
				fmt.Fprintf(&b, "- %s\n", issue)
			}
			fmt.Fprintf(&b, "\n")
		} else {
			fmt.Fprintf(&b, "✅ No issues found.\n\n")
		}
	} else {
		fmt.Fprintf(&b, "ℹ️ No DKIM2 key found (DKIM2 is a draft standard).\n\n")
	}

	// MX
	fmt.Fprintf(&b, "## MX Records\n\n")
	if len(report.MXRecords) > 0 {
		for _, mx := range report.MXRecords {
			fmt.Fprintf(&b, "- `%s`\n", mx)
		}
		fmt.Fprintf(&b, "\n")
	} else {
		fmt.Fprintf(&b, "❌ No MX records found.\n\n")
	}

	// MTA-STS
	fmt.Fprintf(&b, "## MTA-STS\n\n")
	if report.MTASTS != "" {
		fmt.Fprintf(&b, "**Record:** `%s`\n\n", report.MTASTS)
	} else {
		fmt.Fprintf(&b, "❌ No MTA-STS record found.\n\n")
	}

	// TLS-RPT
	fmt.Fprintf(&b, "## TLS-RPT\n\n")
	if report.TLSRPT != "" {
		fmt.Fprintf(&b, "**Record:** `%s`\n\n", report.TLSRPT)
	} else {
		fmt.Fprintf(&b, "❌ No TLS-RPT record found.\n\n")
	}

	// All Issues
	if len(report.Issues) > 0 {
		fmt.Fprintf(&b, "## All Issues (%d)\n\n", len(report.Issues))
		for _, issue := range report.Issues {
			fmt.Fprintf(&b, "- %s\n", issue)
		}
	}

	return b.String()
}
