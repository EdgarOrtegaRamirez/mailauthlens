# AGENTS.md

## Project Overview
MailAuthLens is a Go CLI toolkit for analyzing email authentication configurations (SPF, DKIM, DKIM2, DMARC).

## Project Structure
```
mailauthlens/
├── cmd/mailauthlens/main.go    # CLI entry point
├── internal/
│   ├── spf/spf.go              # SPF parsing & evaluation (RFC 7208)
│   ├── dkim/dkim.go            # DKIM parsing & verification (RFC 6376)
│   ├── dkim2/dkim2.go          # DKIM2 parsing (draft-ietf-dkim-dkim2-spec)
│   ├── dmarc/dmarc.go          # DMARC parsing (RFC 9989)
│   ├── dnslookup/resolver.go   # DNS resolution utilities
│   └── report/report.go        # Report generation
├── *_test.go                   # Tests (co-located with source)
└── go.mod                      # Go module definition
```

## Building
```bash
go build ./...
go build -o mailauthlens ./cmd/mailauthlens
```

## Testing
```bash
go test ./...
```

## Conventions
- No hardcoded secrets — use environment variables
- Proper error handling (no bare returns on errors)
- Type-safe Go code with clear error messages
- Tests must cover happy path and error cases
- Use semantic commit messages
