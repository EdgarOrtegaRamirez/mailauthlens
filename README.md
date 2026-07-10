# MailAuthLens — Email Authentication Intelligence Toolkit

**A comprehensive CLI toolkit for analyzing SPF, DKIM, DKIM2, and DMARC email authentication configurations.**

## Features

- **SPF Analysis** — Parse, validate, and evaluate SPF records per RFC 7208
- **DKIM Verification** — Parse, validate, and verify DKIM signatures per RFC 6376 (with RFC 8301, 8463, 8553, 8616 updates)
- **DKIM2 Support** — Parse and analyze the new DKIM2 standard (draft-ietf-dkim-dkim2-spec-04, July 2026) with chain-of-custody signing
- **DMARCbis (RFC 9989)** — Parse and validate DMARC records with new RFC 9989 additions (psd=, np= tags)
- **MTA-STS & TLS-RPT** — Check MTA-STS and TLS Reporting configurations
- **Multi-format Reports** — Output in text, JSON, or Markdown format
- **Security Scoring** — Automatic 0-100 score with letter grade (A-F)

## Supported Standards

| Standard | Version | Status |
|----------|---------|--------|
| SPF | RFC 7208 | Published |
| DKIM | RFC 6376 + RFC 8301, 8463, 8553, 8616 | Published |
| DKIM2 | draft-ietf-dkim-dkim2-spec-04 | Draft (July 2026) |
| DMARC | RFC 9989 (DMARCbis) | Published (May 2026) |
| MTA-STS | RFC 8461 | Published |
| TLS-RPT | RFC 8460 | Published |

## Installation

```bash
go install github.com/EdgarOrtegaRamirez/mailauthlens/cmd/mailauthlens@latest
```

Or build from source:

```bash
git clone https://github.com/EdgarOrtegaRamirez/mailauthlens.git
cd mailauthlens
go build -o mailauthlens ./cmd/mailauthlens
```

## Quick Start

### Comprehensive Domain Check

```bash
# Full analysis of all email auth records
mailauthlens check gmail.com

# With specific DKIM selector
mailauthlens check gmail.com --selector default

# JSON output
mailauthlens check gmail.com --format json

# Markdown report
mailauthlens check gmail.com --format markdown
```

### Individual Record Checks

```bash
# SPF record analysis
mailauthlens spf example.com

# DKIM key analysis
mailauthlens dkim example.com default

# DKIM2 key analysis (draft standard)
mailauthlens dkim2 example.com default

# DMARC record analysis (RFC 9989)
mailauthlens dmarc example.com --format markdown
```

### DKIM Signature Verification

```bash
# Verify DKIM signature on an email file
mailauthlens verify email.eml
```

### Record Generation

```bash
# Generate SPF record template
mailauthlens generate spf --domain example.com --ip 192.168.1.1

# Generate DMARC record template
mailauthlens generate dmarc --domain example.com --policy reject
```

## Report Format

### Text Output

```
MailAuthLens Report for example.com
Generated: 2026-07-08T22:00:00Z

Security Score: 85/100 (Grade: B)

=== SPF ===
  Record: v=spf1 ip4:192.168.1.0/24 -all
  No issues found.

=== DMARC (RFC 9989) ===
  Record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com
  Policy: reject
  DKIM Alignment: relaxed
  SPF Alignment: relaxed
  No issues found.

=== DKIM ===
  Selector: default
  No issues found.

=== DKIM2 (draft-ietf-dkim-dkim2-spec) ===
  Selector: default
  ℹ️ No DKIM2 key found (DKIM2 is a draft standard).
```

### JSON Output

```json
{
  "domain": "example.com",
  "timestamp": "2026-07-08T22:00:00Z",
  "score": 85,
  "grade": "B",
  "spf": {
    "found": true,
    "record": "v=spf1 ip4:192.168.1.0/24 -all",
    "issues": []
  },
  "dmarc": {
    "found": true,
    "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "policy": "reject",
    "issues": []
  }
}
```

## Security Scoring

The security score (0-100) is calculated based on:

| Factor | Points |
|--------|--------|
| SPF record present | 10 |
| SPF has proper `-all` | 10 |
| DMARC record present | 10 |
| DMARC policy (none/quarantine/reject) | 5-20 |
| DMARC report URIs configured | 5 |
| DKIM key present | 10 |
| DKIM2 key present | 10 |
| MX records configured | 5 |
| MTA-STS configured | 5 |
| TLS-RPT configured | 5 |

## Architecture

```
mailauthlens/
├── cmd/mailauthlens/main.go    # CLI entry point
├── internal/
│   ├── spf/spf.go              # SPF parsing & evaluation (RFC 7208)
│   ├── dkim/dkim.go            # DKIM parsing & verification (RFC 6376)
│   ├── dkim2/dkim2.go          # DKIM2 parsing (draft-ietf-dkim-dkim2-spec)
│   ├── dmarc/dmarc.go          # DMARC parsing (RFC 9989)
│   ├── dnslookup/resolver.go   # DNS resolution utilities
│   └── report/report.go        # Report generation (text/JSON/markdown)
└── go.mod                      # Go module definition
```

## DKIM2 Highlights

DKIM2 (draft-ietf-dkim-dkim2-spec-04) introduces several significant improvements over DKIM1:

- **Chain of Custody**: Each forwarder adds its own signature, maintaining a verifiable chain
- **Message-Instance Headers**: Track changes made to the message at each hop
- **Replay Prevention**: `mf=` (MAIL FROM) and `rt=` (RCPT TO) tags prevent message replay
- **Ed25519 Support**: Modern, faster signature algorithm alongside RSA
- **Delivery Status Notification Authentication**: Links signatures to delivery receipts

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass (`go test ./...`)
5. Submit a pull request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Security

If you discover a security vulnerability, please open a security advisory on GitHub rather than filing a public issue.
