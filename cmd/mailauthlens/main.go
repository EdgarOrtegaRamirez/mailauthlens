// Package main implements the MailAuthLens CLI.
//
// MailAuthLens is an email authentication intelligence toolkit that
// analyzes SPF, DKIM, DKIM2, and DMARC (RFC 9989) configurations.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dkim"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dkim2"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dmarc"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/dnslookup"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/report"
	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/spf"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "check":
		cmdCheck(args)
	case "spf":
		cmdSPF(args)
	case "dkim":
		cmdDKIM(args)
	case "dkim2":
		cmdDKIM2(args)
	case "dmarc":
		cmdDMARC(args)
	case "verify":
		cmdVerify(args)
	case "generate":
		cmdGenerate(args)
	case "version":
		fmt.Printf("MailAuthLens v%s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `MailAuthLens v%s — Email Authentication Intelligence Toolkit

Usage: mailauthlens <command> [options]

Commands:
  check <domain>              Comprehensive check of all email auth records
  spf <domain>                Parse and validate SPF record
  dkim <domain> <selector>    Parse and validate DKIM key record
  dkim2 <domain> <selector>   Parse and validate DKIM2 key record
  dmarc <domain>              Parse and validate DMARC record (RFC 9989)
  verify <file>               Verify DKIM signature on an email file
  generate <type> [options]   Generate auth records (spf, dkim, dmarc)
  version                     Show version
  help                        Show this help

Options:
  --format <text|json|markdown>  Output format (default: text)
  --timeout <seconds>            DNS query timeout (default: 10)
  --selector <name>              DKIM selector (for check command)

Examples:
  mailauthlens check gmail.com
  mailauthlens check gmail.com --selector default --format json
  mailauthlens spf example.com
  mailauthlens dkim example.com default
  mailauthlens dmarc example.com --format markdown
  mailauthlens verify email.eml
  mailauthlens generate spf --domain example.com --ip 192.168.1.1
  mailauthlens generate dmarc --domain example.com --policy reject

Standards supported:
  SPF:    RFC 7208
  DKIM:   RFC 6376 (with RFC 8301, 8463, 8553, 8616 updates)
  DKIM2:  draft-ietf-dkim-dkim2-spec-04 (July 2026)
  DMARC:  RFC 9989 (DMARCbis, obsoleting RFC 7489)
  MTA-STS: RFC 8461
  TLS-RPT: RFC 8460
`, version)
}

// parseOptions parses common CLI options.
type options struct {
	format   string
	timeout  int
	selector string
	domain   string
	ip       string
	policy   string
}

func parseOptions(args []string) (options, []string) {
	opts := options{format: "text", timeout: 10}
	var positional []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 < len(args) {
				opts.format = args[i+1]
				i++
			}
		case "--timeout":
			if i+1 < len(args) {
				if _, err := fmt.Sscanf(args[i+1], "%d", &opts.timeout); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: invalid timeout value %q, using default\n", args[i+1])
				}
				i++
			}
		case "--selector":
			if i+1 < len(args) {
				opts.selector = args[i+1]
				i++
			}
		case "--domain":
			if i+1 < len(args) {
				opts.domain = args[i+1]
				i++
			}
		case "--ip":
			if i+1 < len(args) {
				opts.ip = args[i+1]
				i++
			}
		case "--policy":
			if i+1 < len(args) {
				opts.policy = args[i+1]
				i++
			}
		default:
			positional = append(positional, args[i])
		}
	}

	return opts, positional
}

func newResolver(timeout int) *dnslookup.Resolver {
	return dnslookup.NewResolverWithTimeout(time.Duration(timeout) * time.Second)
}

func cmdCheck(args []string) {
	opts, positional := parseOptions(args)
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Error: domain required")
		os.Exit(1)
	}
	domain := positional[0]

	resolver := newResolver(opts.timeout)

	var dkimSelectors []string
	if opts.selector != "" {
		dkimSelectors = []string{opts.selector}
	} else {
		// Try common selectors
		dkimSelectors = []string{"default", "selector1", "selector2", "google", "s1", "k1"}
	}

	rep := report.GenerateDomainReport(domain, resolver, dkimSelectors, dkimSelectors)

	output, err := report.FormatReport(rep, report.Format(opts.format))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(output)
}

func cmdSPF(args []string) {
	opts, positional := parseOptions(args)
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Error: domain required")
		os.Exit(1)
	}
	domain := positional[0]

	resolver := newResolver(opts.timeout)
	rec, err := resolver.LookupSPF(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	issues := spf.Validate(rec)

	switch opts.format {
	case "json":
		printJSON(map[string]interface{}{
			"domain":     domain,
			"record":     rec.Raw,
			"mechanisms": rec.Mechanisms,
			"issues":     issues,
			"redirect":   rec.Redirect,
		})
	case "markdown":
		fmt.Printf("# SPF Report: %s\n\n", domain)
		fmt.Printf("**Record:** `%s`\n\n", rec.Raw)
		fmt.Printf("**Mechanisms:**\n\n")
		for _, m := range rec.Mechanisms {
			fmt.Printf("- `%s`\n", m.String())
		}
		if rec.Redirect != "" {
			fmt.Printf("\n**Redirect:** `%s`\n", rec.Redirect)
		}
		fmt.Printf("\n")
		if len(issues) > 0 {
			fmt.Printf("**Issues:**\n\n")
			for _, issue := range issues {
				fmt.Printf("- %s\n", issue)
			}
		} else {
			fmt.Printf("✅ No issues found.\n")
		}
	default:
		fmt.Printf("SPF Record for %s\n", domain)
		fmt.Printf("========================\n")
		fmt.Printf("Record: %s\n\n", rec.Raw)
		fmt.Printf("Mechanisms:\n")
		for _, m := range rec.Mechanisms {
			fmt.Printf("  %s\n", m.String())
		}
		if rec.Redirect != "" {
			fmt.Printf("\nRedirect: %s\n", rec.Redirect)
		}
		fmt.Printf("\nIssues (%d):\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		if len(issues) == 0 {
			fmt.Printf("  (none)\n")
		}
	}
}

func cmdDKIM(args []string) {
	opts, positional := parseOptions(args)
	if len(positional) < 2 {
		fmt.Fprintln(os.Stderr, "Error: domain and selector required")
		os.Exit(1)
	}
	domain := positional[0]
	selector := positional[1]

	resolver := newResolver(opts.timeout)
	record, err := resolver.LookupDKIMKey(selector, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	keyRec, err := dkim.ParseKeyRecord(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing key: %v\n", err)
		os.Exit(1)
	}

	issues := dkim.Validate(nil, keyRec)

	switch opts.format {
	case "json":
		printJSON(map[string]interface{}{
			"domain":   domain,
			"selector": selector,
			"record":   record,
			"keyType":  keyRec.KeyType,
			"flags":    keyRec.Flags,
			"issues":   issues,
			"revoked":  keyRec.IsRevoked(),
		})
	case "markdown":
		fmt.Printf("# DKIM Report: %s (selector: %s)\n\n", domain, selector)
		fmt.Printf("**Record:** `%s`\n\n", record)
		fmt.Printf("| Tag | Value |\n|-----|-------|\n")
		fmt.Printf("| Key Type (k=) | %s |\n", keyRec.KeyType)
		fmt.Printf("| Service (s=) | %s |\n", keyRec.ServiceType)
		fmt.Printf("| Flags (t=) | %s |\n", keyRec.Flags)
		fmt.Printf("| Hash Algorithms (h=) | %s |\n", keyRec.HashAlgorithms)
		fmt.Printf("| Revoked | %v |\n\n", keyRec.IsRevoked())
		if len(issues) > 0 {
			fmt.Printf("**Issues:**\n\n")
			for _, issue := range issues {
				fmt.Printf("- %s\n", issue)
			}
		} else {
			fmt.Printf("✅ No issues found.\n")
		}
	default:
		fmt.Printf("DKIM Key Record for %s (selector: %s)\n", domain, selector)
		fmt.Printf("==========================================\n")
		fmt.Printf("Record: %s\n\n", record)
		fmt.Printf("Key Type: %s\n", keyRec.KeyType)
		fmt.Printf("Service Type: %s\n", keyRec.ServiceType)
		fmt.Printf("Flags: %s\n", keyRec.Flags)
		fmt.Printf("Hash Algorithms: %s\n", keyRec.HashAlgorithms)
		fmt.Printf("Revoked: %v\n\n", keyRec.IsRevoked())
		fmt.Printf("Issues (%d):\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		if len(issues) == 0 {
			fmt.Printf("  (none)\n")
		}
	}
}

func cmdDKIM2(args []string) {
	opts, positional := parseOptions(args)
	if len(positional) < 2 {
		fmt.Fprintln(os.Stderr, "Error: domain and selector required")
		os.Exit(1)
	}
	domain := positional[0]
	selector := positional[1]

	resolver := newResolver(opts.timeout)
	record, err := resolver.LookupDKIM2Key(selector, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	keyRec, err := dkim2.ParseKeyRecord(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing key: %v\n", err)
		os.Exit(1)
	}

	issues := dkim2.Validate(nil, keyRec)

	switch opts.format {
	case "json":
		printJSON(map[string]interface{}{
			"domain":   domain,
			"selector": selector,
			"record":   record,
			"keyType":  keyRec.KeyType,
			"flags":    keyRec.Flags,
			"issues":   issues,
			"revoked":  keyRec.IsRevoked(),
		})
	default:
		fmt.Printf("DKIM2 Key Record for %s (selector: %s)\n", domain, selector)
		fmt.Printf("===========================================\n")
		fmt.Printf("Record: %s\n\n", record)
		fmt.Printf("Key Type: %s\n", keyRec.KeyType)
		fmt.Printf("Flags: %s\n", keyRec.Flags)
		fmt.Printf("Revoked: %v\n\n", keyRec.IsRevoked())
		fmt.Printf("Issues (%d):\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		if len(issues) == 0 {
			fmt.Printf("  (none)\n")
		}
	}
}

func cmdDMARC(args []string) {
	opts, positional := parseOptions(args)
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Error: domain required")
		os.Exit(1)
	}
	domain := positional[0]

	resolver := newResolver(opts.timeout)
	record, err := resolver.LookupDMARC(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	rec, err := dmarc.Parse(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing record: %v\n", err)
		os.Exit(1)
	}

	issues := dmarc.Validate(rec)

	switch opts.format {
	case "json":
		printJSON(map[string]interface{}{
			"domain":          domain,
			"record":          record,
			"policy":          rec.Policy,
			"subdomainPolicy": rec.SubdomainPolicy,
			"adkim":           rec.AlignmentDKIM,
			"aspf":            rec.AlignmentSPF,
			"psd":             rec.PSD,
			"np":              rec.NPDomainPolicy,
			"rua":             rec.AggregateReportURIs,
			"ruf":             rec.FailureReportURIs,
			"issues":          issues,
		})
	case "markdown":
		fmt.Printf("# DMARC Report: %s (RFC 9989)\n\n", domain)
		fmt.Printf("**Record:** `%s`\n\n", record)
		fmt.Printf("| Tag | Value |\n|-----|-------|\n")
		fmt.Printf("| Policy (p=) | %s |\n", rec.Policy)
		if rec.HasSubdomainPolicy {
			fmt.Printf("| Subdomain Policy (sp=) | %s |\n", rec.SubdomainPolicy)
		}
		fmt.Printf("| DKIM Alignment (adkim=) | %s |\n", rec.AlignmentDKIM)
		fmt.Printf("| SPF Alignment (aspf=) | %s |\n", rec.AlignmentSPF)
		if rec.HasPSD {
			fmt.Printf("| PSD (psd=) | %s |\n", rec.PSD)
		}
		if rec.HasNPDomainPolicy {
			fmt.Printf("| NP Policy (np=) | %s |\n", rec.NPDomainPolicy)
		}
		if len(rec.AggregateReportURIs) > 0 {
			fmt.Printf("| Aggregate Reports (rua=) | %s |\n", strings.Join(rec.AggregateReportURIs, ", "))
		}
		if len(rec.FailureReportURIs) > 0 {
			fmt.Printf("| Failure Reports (ruf=) | %s |\n", strings.Join(rec.FailureReportURIs, ", "))
		}
		fmt.Printf("\n")
		if len(issues) > 0 {
			fmt.Printf("**Issues:**\n\n")
			for _, issue := range issues {
				fmt.Printf("- %s\n", issue)
			}
		} else {
			fmt.Printf("✅ No issues found.\n")
		}
	default:
		fmt.Printf("DMARC Record for %s (RFC 9989)\n", domain)
		fmt.Printf("================================\n")
		fmt.Printf("Record: %s\n\n", record)
		fmt.Printf("Policy: %s\n", rec.Policy)
		if rec.HasSubdomainPolicy {
			fmt.Printf("Subdomain Policy: %s\n", rec.SubdomainPolicy)
		}
		fmt.Printf("DKIM Alignment: %s\n", rec.AlignmentDKIM)
		fmt.Printf("SPF Alignment: %s\n", rec.AlignmentSPF)
		if rec.HasPSD {
			fmt.Printf("PSD Flag: %s\n", rec.PSD)
		}
		if rec.HasNPDomainPolicy {
			fmt.Printf("NP Policy: %s\n", rec.NPDomainPolicy)
		}
		if len(rec.AggregateReportURIs) > 0 {
			fmt.Printf("Aggregate Report URIs: %s\n", strings.Join(rec.AggregateReportURIs, ", "))
		}
		if len(rec.FailureReportURIs) > 0 {
			fmt.Printf("Failure Report URIs: %s\n", strings.Join(rec.FailureReportURIs, ", "))
		}
		fmt.Printf("\nIssues (%d):\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		if len(issues) == 0 {
			fmt.Printf("  (none)\n")
		}
	}
}

func cmdVerify(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: email file required")
		os.Exit(1)
	}
	filename := args[0]

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	resolver := dnslookup.NewResolver()
	result, err := dkim.Verify(data, resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("DKIM Verification Result\n")
	fmt.Printf("=======================\n")
	fmt.Printf("Result: %s\n", result.Result)
	fmt.Printf("Reason: %s\n", result.Reason)
	if result.Signature != nil {
		fmt.Printf("\nSignature Details:\n")
		fmt.Printf("  Domain: %s\n", result.Signature.Domain)
		fmt.Printf("  Selector: %s\n", result.Signature.Selector)
		fmt.Printf("  Algorithm: %s\n", result.Signature.Algorithm)
		fmt.Printf("  Canonicalization: %s\n", result.Signature.Canonicalization)
	}
	if result.KeyRecord != nil {
		fmt.Printf("\nKey Record:\n")
		fmt.Printf("  Key Type: %s\n", result.KeyRecord.KeyType)
		fmt.Printf("  Flags: %s\n", result.KeyRecord.Flags)
		fmt.Printf("  Revoked: %v\n", result.KeyRecord.IsRevoked())
	}
}

func cmdGenerate(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: type required (spf, dkim, dmarc)")
		os.Exit(1)
	}
	genType := args[0]
	opts, _ := parseOptions(args[1:])

	switch genType {
	case "spf":
		if opts.domain == "" {
			fmt.Fprintln(os.Stderr, "Error: --domain required")
			os.Exit(1)
		}
		record := "v=spf1"
		if opts.ip != "" {
			record += " ip4:" + opts.ip
		}
		record += " -all"
		fmt.Printf("SPF record for %s:\n%s\n", opts.domain, record)
		fmt.Printf("\nPublish as a TXT record for %s\n", opts.domain)

	case "dmarc":
		if opts.domain == "" {
			fmt.Fprintln(os.Stderr, "Error: --domain required")
			os.Exit(1)
		}
		policy := opts.policy
		if policy == "" {
			policy = "none"
		}
		record := fmt.Sprintf("v=DMARC1; p=%s; rua=dmarc@%s", policy, opts.domain)
		fmt.Printf("DMARC record for %s:\n%s\n", opts.domain, record)
		fmt.Printf("\nPublish as a TXT record for _dmarc.%s\n", opts.domain)

	case "dkim":
		fmt.Println("DKIM key generation requires a key pair.")
		fmt.Println("Use openssl to generate a key pair:")
		fmt.Println("  openssl genrsa -out private.key 2048")
		fmt.Println("  openssl rsa -in private.key -pubout -outform der | openssl base64 -A")
		fmt.Println("\nThen publish the base64-encoded public key as a TXT record at:")
		fmt.Println("  <selector>._domainkey.<domain>")

	default:
		fmt.Fprintf(os.Stderr, "Unknown generate type: %s\n", genType)
		os.Exit(1)
	}
}

// printJSON prints a value as indented JSON.
func printJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
