# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in MailAuthLens, please:

1. **Do not** open a public GitHub issue
2. Email the maintainer directly or use GitHub's private vulnerability reporting feature
3. Include a detailed description of the vulnerability
4. Allow reasonable time for a response before public disclosure

## Security Best Practices

When using MailAuthLens:

- Never commit sensitive DNS data or private keys
- Use `--timeout` flag appropriately for your network conditions
- Validate DNS responses before processing (done by default)
- Keep the tool updated for latest security patches

## Security Considerations

### DNS Lookups

MailAuthLens performs DNS lookups to email authentication records. These lookups:
- Are cached with a 5-minute TTL to reduce attack surface
- Time out after 10 seconds (configurable via `--timeout`)
- Use the system's standard DNS resolver

### No Network Exfiltration

MailAuthLens only performs authorized DNS queries for email authentication records. It does not:
- Exfiltrate DNS query data to third parties
- Connect to external APIs during analysis
- Store query results persistently
