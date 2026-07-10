// Package dnslookup provides DNS resolution utilities for email
// authentication records (SPF, DKIM, DMARC, DKIM2, MTA-STS, etc.).
package dnslookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/EdgarOrtegaRamirez/mailauthlens/internal/spf"
)

// contextWithTimeout creates a context with the DNS query timeout.
func contextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// Resolver implements DNS resolution for email authentication records.
// It uses the standard library net package and caches results.
type Resolver struct {
	// netResolver is the underlying DNS resolver.
	netResolver *net.Resolver

	// cache is a simple TTL cache for TXT records.
	cache *txtCache

	// timeout is the DNS query timeout.
	timeout time.Duration
}

// NewResolver creates a new Resolver with default settings.
func NewResolver() *Resolver {
	return &Resolver{
		netResolver: net.DefaultResolver,
		cache:       newTXTCache(5 * time.Minute),
		timeout:     10 * time.Second,
	}
}

// NewResolverWithTimeout creates a new Resolver with a custom timeout.
func NewResolverWithTimeout(timeout time.Duration) *Resolver {
	return &Resolver{
		netResolver: &net.Resolver{},
		cache:       newTXTCache(5 * time.Minute),
		timeout:     timeout,
	}
}

// LookupTXT performs a DNS TXT record lookup.
func (r *Resolver) LookupTXT(domain string) ([]string, error) {
	// Check cache
	if cached, ok := r.cache.get(domain); ok {
		return cached, nil
	}

	ctx, cancel := contextWithTimeout(r.timeout)
	defer cancel()

	records, err := r.netResolver.LookupTXT(ctx, domain)
	if err != nil {
		// Check for NXDOMAIN-like errors
		if isNXDomain(err) {
			r.cache.set(domain, nil)
			return nil, fmt.Errorf("no TXT records found for %s: %w", domain, err)
		}
		return nil, fmt.Errorf("TXT lookup failed for %s: %w", domain, err)
	}

	// Join multi-string TXT records (each TXT record may have multiple strings)
	// In Go's net.LookupTXT, each element is a separate TXT record's concatenated strings.
	// We return them as-is.
	r.cache.set(domain, records)
	return records, nil
}

// LookupSPF looks up the SPF record for a domain.
// Returns the first TXT record that starts with "v=spf1".
func (r *Resolver) LookupSPF(domain string) (*spf.Record, error) {
	records, err := r.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	for _, rec := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
			return spf.Parse(rec)
		}
	}

	return nil, fmt.Errorf("no SPF record found for %s", domain)
}

// LookupDMARC looks up the DMARC record for a domain.
// Returns the first TXT record at _dmarc.<domain> that starts with "v=DMARC1".
func (r *Resolver) LookupDMARC(domain string) (string, error) {
	queryName := "_dmarc." + domain
	records, err := r.LookupTXT(queryName)
	if err != nil {
		return "", err
	}

	for _, rec := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=dmarc1") {
			return rec, nil
		}
	}

	return "", fmt.Errorf("no DMARC record found for %s", domain)
}

// LookupDKIMKey looks up a DKIM public key record.
func (r *Resolver) LookupDKIMKey(selector, domain string) (string, error) {
	queryName := selector + "._domainkey." + domain
	records, err := r.LookupTXT(queryName)
	if err != nil {
		return "", err
	}

	for _, rec := range records {
		// DKIM key records may or may not have v= tag
		// Look for records with p= tag
		if strings.Contains(rec, "p=") {
			return rec, nil
		}
	}

	if len(records) > 0 {
		return records[0], nil
	}

	return "", fmt.Errorf("no DKIM key found at %s", queryName)
}

// LookupDKIM2Key looks up a DKIM2 public key record.
// DKIM2 keys are stored in the same _domainkey subdomain as DKIM1.
func (r *Resolver) LookupDKIM2Key(selector, domain string) (string, error) {
	return r.LookupDKIMKey(selector, domain)
}

// LookupIP performs A and AAAA record lookups.
func (r *Resolver) LookupIP(domain string) ([]net.IP, error) {
	ctx, cancel := contextWithTimeout(r.timeout)
	defer cancel()

	ips, err := r.netResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	result := make([]net.IP, len(ips))
	for i, ip := range ips {
		result[i] = ip.IP
	}
	return result, nil
}

// LookupMX performs MX record lookups.
func (r *Resolver) LookupMX(domain string) ([]*net.MX, error) {
	ctx, cancel := contextWithTimeout(r.timeout)
	defer cancel()

	return r.netResolver.LookupMX(ctx, domain)
}

// LookupPTR performs PTR record lookups.
func (r *Resolver) LookupPTR(ip string) ([]string, error) {
	ctx, cancel := contextWithTimeout(r.timeout)
	defer cancel()

	names, err := r.netResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}
	return names, nil
}

// LookupMTASTS looks up MTA-STS records for a domain.
func (r *Resolver) LookupMTASTS(domain string) (string, error) {
	queryName := "_mta-sts." + domain
	records, err := r.LookupTXT(queryName)
	if err != nil {
		return "", err
	}

	for _, rec := range records {
		if strings.Contains(rec, "v=STS1") {
			return rec, nil
		}
	}

	return "", fmt.Errorf("no MTA-STS record found for %s", domain)
}

// LookupTLSRPT looks up TLS Reporting records for a domain.
func (r *Resolver) LookupTLSRPT(domain string) (string, error) {
	queryName := "_smtp._tls." + domain
	records, err := r.LookupTXT(queryName)
	if err != nil {
		return "", err
	}

	for _, rec := range records {
		if strings.Contains(rec, "v=TLSRPT") {
			return rec, nil
		}
	}

	return "", fmt.Errorf("no TLS-RPT record found for %s", domain)
}

// LookupMXRecordsForDomain looks up MX records and returns them as strings.
func (r *Resolver) LookupMXRecordsForDomain(domain string) ([]string, error) {
	mxs, err := r.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(mxs))
	for i, mx := range mxs {
		result[i] = fmt.Sprintf("%d %s", mx.Pref, mx.Host)
	}
	return result, nil
}

// CheckDomain checks all email authentication records for a domain.
// Returns a comprehensive report of all findings.
type DomainCheck struct {
	Domain      string
	SPFRecord   string
	SPFError    string
	DMARCRecord string
	DMARCError  string
	MXRecords   []string
	MXError     string
	MTASTS      string
	MTASTSError string
	TLSRPT      string
	TLSRPTError string
	HasDNSSEC   bool
}

// CheckDomain performs a comprehensive check of all email authentication
// records for a domain.
func (r *Resolver) CheckDomain(domain string) *DomainCheck {
	check := &DomainCheck{Domain: domain}

	// SPF
	if spfRec, err := r.LookupSPF(domain); err == nil {
		check.SPFRecord = spfRec.Raw
	} else {
		check.SPFError = err.Error()
	}

	// DMARC
	if dmarcRec, err := r.LookupDMARC(domain); err == nil {
		check.DMARCRecord = dmarcRec
	} else {
		check.DMARCError = err.Error()
	}

	// MX
	if mxs, err := r.LookupMXRecordsForDomain(domain); err == nil {
		check.MXRecords = mxs
	} else {
		check.MXError = err.Error()
	}

	// MTA-STS
	if rec, err := r.LookupMTASTS(domain); err == nil {
		check.MTASTS = rec
	} else {
		check.MTASTSError = err.Error()
	}

	// TLS-RPT
	if rec, err := r.LookupTLSRPT(domain); err == nil {
		check.TLSRPT = rec
	} else {
		check.TLSRPTError = err.Error()
	}

	return check
}

// txtCache is a simple TTL cache for TXT records.
type txtCache struct {
	mu      sync.RWMutex
	entries map[string]txtCacheEntry
	ttl     time.Duration
}

type txtCacheEntry struct {
	records   []string
	expiresAt time.Time
}

func newTXTCache(ttl time.Duration) *txtCache {
	return &txtCache{
		entries: make(map[string]txtCacheEntry),
		ttl:     ttl,
	}
}

func (c *txtCache) get(key string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.records, true
}

func (c *txtCache) set(key string, records []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = txtCacheEntry{
		records:   records,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// isNXDomain checks if an error is a NXDOMAIN (non-existent domain) error.
func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "NXDOMAIN") ||
		strings.Contains(msg, "not found")
}
