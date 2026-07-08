// Package dkim2 implements parsing of DKIM2 (DomainKeys Identified Mail v2)
// signatures per draft-ietf-dkim-dkim2-spec-04 (July 2026).
//
// DKIM2 is the successor to DKIM (RFC 6376) with chain-of-custody signing,
// replay prevention, and Delivery Status Notification authentication.
// This package focuses on parsing and analyzing DKIM2 signatures and
// key records. Full cryptographic verification is supported for
// RSA and Ed25519 keys.
package dkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// Signature represents a parsed DKIM2-Signature header field.
//
// DKIM2 uses a different tag set than DKIM1:
//   - i= sequence number (1 for originator, incrementing for forwarders)
//   - m= highest numbered Message-Instance header field
//   - n= nonce value
//   - t= signature timestamp
//   - mf= MAIL FROM used when sending
//   - rt= RCPT TO value(s) used when sending
//   - nd= domain of the next DKIM2-Signature header field
//   - d= signing domain
//   - s= signature value(s)
//   - f= flags
type Signature struct {
	// SequenceNumber (i= tag). 1 for originator, incrementing for forwarders.
	SequenceNumber int

	// MessageInstance (m= tag). Highest numbered Message-Instance header.
	MessageInstance int

	// Nonce (n= tag). Nonce value (max 64 chars).
	Nonce string

	// Timestamp (t= tag). Signature timestamp.
	Timestamp int64

	// MailFrom (mf= tag). The MAIL FROM used when sending.
	MailFrom string

	// RcptTo (rt= tag). The RCPT TO value(s) used when sending.
	RcptTo string

	// NextDomain (nd= tag). Domain of the next DKIM2-Signature header.
	NextDomain string

	// Domain (d= tag). The signing domain.
	Domain string

	// SignatureValue (s= tag). Base64-encoded signature value(s).
	SignatureValue string

	// Flags (f= tag). Flags.
	Flags string

	// Raw is the raw header value.
	Raw string
}

// Parse parses a DKIM2-Signature header value into a Signature struct.
func Parse(headerValue string) (*Signature, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return nil, fmt.Errorf("empty DKIM2-Signature header")
	}

	unfolded := unfold(headerValue)
	sig := &Signature{
		Raw:       unfolded,
		Timestamp: -1,
	}

	tags, err := parseTagList(unfolded)
	if err != nil {
		return nil, fmt.Errorf("parse tag list: %w", err)
	}

	for _, tag := range tags {
		switch tag.Name {
		case "i":
			var n int
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				sig.SequenceNumber = n
			}
		case "m":
			var n int
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				sig.MessageInstance = n
			}
		case "n":
			sig.Nonce = tag.Value
		case "t":
			var n int64
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				sig.Timestamp = n
			}
		case "mf":
			sig.MailFrom = tag.Value
		case "rt":
			sig.RcptTo = tag.Value
		case "nd":
			sig.NextDomain = tag.Value
		case "d":
			sig.Domain = tag.Value
		case "s":
			sig.SignatureValue = tag.Value
		case "f":
			sig.Flags = tag.Value
		}
	}

	// Validate required tags
	if sig.Domain == "" {
		return nil, fmt.Errorf("missing required d= tag")
	}
	if sig.SignatureValue == "" {
		return nil, fmt.Errorf("missing required s= tag")
	}
	if sig.SequenceNumber < 1 {
		return nil, fmt.Errorf("missing or invalid i= tag (must be >= 1)")
	}

	return sig, nil
}

// Tag represents a single tag-value pair in a DKIM2 tag list.
type Tag struct {
	Name  string
	Value string
}

// parseTagList parses a DKIM2 tag-value list (tag=value;tag=value;...).
func parseTagList(text string) ([]Tag, error) {
	var tags []Tag
	parts := strings.Split(text, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx < 0 {
			return nil, fmt.Errorf("malformed tag: %q", part)
		}
		tags = append(tags, Tag{
			Name:  strings.TrimSpace(part[:idx]),
			Value: strings.TrimSpace(part[idx+1:]),
		})
	}
	return tags, nil
}

// unfold removes CRLF followed by WSP from a header value.
func unfold(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n ", " ")
	text = strings.ReplaceAll(text, "\n\t", " ")
	return text
}

// KeyRecord represents a DKIM2 public key record from DNS.
// DKIM2 keys are stored in the same _domainkey subdomain as DKIM1 keys.
type KeyRecord struct {
	// Version (v= tag).
	Version string

	// KeyType (k= tag). "rsa" or "ed25519".
	KeyType string

	// KeyData (p= tag). Base64-encoded public key.
	KeyData string

	// Flags (t= tag).
	Flags string

	// Notes (n= tag).
	Notes string

	// Raw is the original TXT record text.
	Raw string
}

// ParseKeyRecord parses a DKIM2 DNS TXT record.
func ParseKeyRecord(text string) (*KeyRecord, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty DKIM2 key record")
	}

	unfolded := unfold(text)
	rec := &KeyRecord{Raw: unfolded, KeyType: "rsa"}

	tags, err := parseTagList(unfolded)
	if err != nil {
		return nil, fmt.Errorf("parse tag list: %w", err)
	}

	for _, tag := range tags {
		switch tag.Name {
		case "v":
			rec.Version = tag.Value
		case "k":
			rec.KeyType = tag.Value
		case "p":
			rec.KeyData = tag.Value
		case "t":
			rec.Flags = tag.Value
		case "n":
			rec.Notes = tag.Value
		}
	}

	if rec.KeyData == "" {
		return nil, fmt.Errorf("DKIM2 key has been revoked (p= tag is empty)")
	}

	return rec, nil
}

// IsRevoked returns true if the key has been revoked.
func (k *KeyRecord) IsRevoked() bool {
	return k.KeyData == ""
}

// HasFlag checks if the key record has a specific flag.
func (k *KeyRecord) HasFlag(flag string) bool {
	flags := strings.Split(k.Flags, ":")
	for _, f := range flags {
		if strings.TrimSpace(f) == flag {
			return true
		}
	}
	return false
}

// PublicKey returns the parsed public key.
func (k *KeyRecord) PublicKey() (crypto.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.KeyData))
	if err != nil {
		return nil, fmt.Errorf("decode key data: %w", err)
	}

	switch k.KeyType {
	case "rsa", "":
		return parseRSAPublicKey(keyBytes)
	case "ed25519":
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 key length: %d (expected %d)", len(keyBytes), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(keyBytes), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.KeyType)
	}
}

// parseRSAPublicKey parses a DER-encoded RSA public key (PKCS#1).
func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	if len(der) < 11 {
		return nil, fmt.Errorf("RSA key data too short")
	}

	idx := 0
	if der[idx] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE tag, got 0x%02x", der[idx])
	}
	idx++

	_, idx, err := parseDERLength(der, idx)
	if err != nil {
		return nil, fmt.Errorf("parse SEQUENCE length: %w", err)
	}

	modulus, idx, err := parseDERInteger(der, idx)
	if err != nil {
		return nil, fmt.Errorf("parse modulus: %w", err)
	}

	exponent, _, err := parseDERInteger(der, idx)
	if err != nil {
		return nil, fmt.Errorf("parse exponent: %w", err)
	}

	pub := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}
	if pub.E == 0 {
		return nil, fmt.Errorf("invalid public exponent: 0")
	}
	return pub, nil
}

// parseDERLength parses a DER length field.
func parseDERLength(der []byte, idx int) (int, int, error) {
	if idx >= len(der) {
		return 0, idx, fmt.Errorf("unexpected end of data")
	}
	b := der[idx]
	idx++
	if b < 0x80 {
		return int(b), idx, nil
	}
	numBytes := int(b & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, idx, fmt.Errorf("invalid length encoding")
	}
	if idx+numBytes > len(der) {
		return 0, idx, fmt.Errorf("length bytes exceed data")
	}
	var length int
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(der[idx+i])
	}
	idx += numBytes
	return length, idx, nil
}

// parseDERInteger parses a DER INTEGER field.
func parseDERInteger(der []byte, idx int) (*big.Int, int, error) {
	if idx >= len(der) {
		return nil, idx, fmt.Errorf("unexpected end of data")
	}
	if der[idx] != 0x02 {
		return nil, idx, fmt.Errorf("expected INTEGER tag, got 0x%02x", der[idx])
	}
	idx++

	length, idx, err := parseDERLength(der, idx)
	if err != nil {
		return nil, idx, err
	}
	if idx+length > len(der) {
		return nil, idx, fmt.Errorf("integer data exceeds available bytes")
	}

	value := new(big.Int).SetBytes(der[idx : idx+length])
	idx += length
	return value, idx, nil
}

// MessageInstance represents a parsed Message-Instance header field.
// DKIM2 uses Message-Instance headers to track changes to the message
// as it passes through intermediaries (forwarders/revisers).
type MessageInstance struct {
	// SequenceNumber (i= tag). The instance number.
	SequenceNumber int

	// Domain (d= tag). The domain that created this instance.
	Domain string

	// Timestamp (t= tag). When this instance was created.
	Timestamp int64

	// HashAlgorithm (ha= tag). Hash algorithm used.
	HashAlgorithm string

	// BodyHash (bh= tag). Hash of the message body at this instance.
	BodyHash string

	// HeaderHash (hh= tag). Hash of the signed headers.
	HeaderHash string

	// Recipe (r= tag). JSON recipe for reconstructing previous version.
	Recipe string

	// Raw is the raw header value.
	Raw string
}

// ParseMessageInstance parses a Message-Instance header value.
func ParseMessageInstance(headerValue string) (*MessageInstance, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return nil, fmt.Errorf("empty Message-Instance header")
	}

	unfolded := unfold(headerValue)
	mi := &MessageInstance{Raw: unfolded, Timestamp: -1}

	tags, err := parseTagList(unfolded)
	if err != nil {
		return nil, fmt.Errorf("parse tag list: %w", err)
	}

	for _, tag := range tags {
		switch tag.Name {
		case "i":
			var n int
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				mi.SequenceNumber = n
			}
		case "d":
			mi.Domain = tag.Value
		case "t":
			var n int64
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				mi.Timestamp = n
			}
		case "ha":
			mi.HashAlgorithm = tag.Value
		case "bh":
			mi.BodyHash = tag.Value
		case "hh":
			mi.HeaderHash = tag.Value
		case "r":
			mi.Recipe = tag.Value
		}
	}

	if mi.SequenceNumber < 1 {
		return nil, fmt.Errorf("missing or invalid i= tag")
	}
	if mi.Domain == "" {
		return nil, fmt.Errorf("missing required d= tag")
	}

	return mi, nil
}

// ChainOfCustody represents the full chain of DKIM2 signatures and
// message instances in a message.
type ChainOfCustody struct {
	// Signatures is the list of DKIM2-Signature headers, ordered by i=.
	Signatures []*Signature

	// MessageInstances is the list of Message-Instance headers, ordered by i=.
	MessageInstances []*MessageInstance
}

// ParseChain parses all DKIM2-Signature and Message-Instance headers
// from a list of email headers.
func ParseChain(headers []Header) (*ChainOfCustody, error) {
	chain := &ChainOfCustody{}

	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			sig, err := Parse(h.Value)
			if err != nil {
				return nil, fmt.Errorf("parse DKIM2-Signature: %w", err)
			}
			chain.Signatures = append(chain.Signatures, sig)
		}
		if strings.EqualFold(h.Name, "message-instance") {
			mi, err := ParseMessageInstance(h.Value)
			if err != nil {
				return nil, fmt.Errorf("parse Message-Instance: %w", err)
			}
			chain.MessageInstances = append(chain.MessageInstances, mi)
		}
	}

	// Sort by sequence number
	sortSignatures(chain.Signatures)
	sortMessageInstances(chain.MessageInstances)

	return chain, nil
}

// sortSignatures sorts signatures by sequence number.
func sortSignatures(sigs []*Signature) {
	for i := 1; i < len(sigs); i++ {
		for j := i; j > 0 && sigs[j].SequenceNumber < sigs[j-1].SequenceNumber; j-- {
			sigs[j], sigs[j-1] = sigs[j-1], sigs[j]
		}
	}
}

// sortMessageInstances sorts message instances by sequence number.
func sortMessageInstances(mis []*MessageInstance) {
	for i := 1; i < len(mis); i++ {
		for j := i; j > 0 && mis[j].SequenceNumber < mis[j-1].SequenceNumber; j-- {
			mis[j], mis[j-1] = mis[j-1], mis[j]
		}
	}
}

// Header represents an email header.
type Header struct {
	Name  string
	Value string
}

// ValidateChain checks a DKIM2 chain of custody for issues.
func ValidateChain(chain *ChainOfCustody) []string {
	var issues []string

	if chain == nil {
		return []string{"nil chain"}
	}

	if len(chain.Signatures) == 0 {
		issues = append(issues, "no DKIM2-Signature headers found")
		return issues
	}

	// Check sequence numbering (must be 1, 2, 3, ... with no gaps)
	for i, sig := range chain.Signatures {
		expected := i + 1
		if sig.SequenceNumber != expected {
			issues = append(issues, fmt.Sprintf("signature sequence gap: expected i=%d, got i=%d", expected, sig.SequenceNumber))
		}
	}

	// Check that each signature references the correct message instance
	for _, sig := range chain.Signatures {
		if sig.MessageInstance > 0 {
			found := false
			for _, mi := range chain.MessageInstances {
				if mi.SequenceNumber == sig.MessageInstance {
					found = true
					break
				}
			}
			if !found {
				issues = append(issues, fmt.Sprintf("signature i=%d references non-existent Message-Instance m=%d", sig.SequenceNumber, sig.MessageInstance))
			}
		}
	}

	// Check chain linkage (nd= of signature N should match d= of signature N+1)
	for i := 0; i < len(chain.Signatures)-1; i++ {
		curr := chain.Signatures[i]
		next := chain.Signatures[i+1]
		if curr.NextDomain != "" && curr.NextDomain != next.Domain {
			issues = append(issues, fmt.Sprintf("chain linkage broken: signature i=%d nd=%s but signature i=%d d=%s",
				curr.SequenceNumber, curr.NextDomain, next.SequenceNumber, next.Domain))
		}
	}

	// Check nonce length (max 64 chars per spec)
	for _, sig := range chain.Signatures {
		if len(sig.Nonce) > 64 {
			issues = append(issues, fmt.Sprintf("signature i=%d nonce exceeds 64 character limit", sig.SequenceNumber))
		}
	}

	return issues
}

// DNSQueryName returns the DNS query name for a DKIM2 key.
// DKIM2 uses the same _domainkey subdomain as DKIM1.
func DNSQueryName(selector, domain string) string {
	return selector + "._domainkey." + domain
}

// VerifyResult represents the outcome of DKIM2 verification.
type VerifyResult struct {
	Result    string // "pass", "fail", "temperror", "permerror", "none"
	Reason    string
	Signature *Signature
	KeyRecord *KeyRecord
	Domain    string
}

// VerifySignature verifies a single DKIM2 signature against a hash.
func VerifySignature(sig *Signature, keyRec *KeyRecord, messageHash []byte) (*VerifyResult, error) {
	result := &VerifyResult{
		Signature: sig,
		Domain:    sig.Domain,
		KeyRecord: keyRec,
	}

	if keyRec.IsRevoked() {
		result.Result = "permerror"
		result.Reason = "DKIM2 key has been revoked"
		return result, nil
	}

	pubKey, err := keyRec.PublicKey()
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("parse public key: %v", err)
		return result, nil
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig.SignatureValue)
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("decode signature: %v", err)
		return result, nil
	}

	switch keyRec.KeyType {
	case "rsa", "":
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			result.Result = "permerror"
			result.Reason = "expected RSA public key"
			return result, nil
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, messageHash, sigBytes); err != nil {
			result.Result = "fail"
			result.Reason = fmt.Sprintf("RSA verification failed: %v", err)
			return result, nil
		}
	case "ed25519":
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			result.Result = "permerror"
			result.Reason = "expected Ed25519 public key"
			return result, nil
		}
		if !ed25519.Verify(edKey, messageHash, sigBytes) {
			result.Result = "fail"
			result.Reason = "Ed25519 verification failed"
			return result, nil
		}
	default:
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("unsupported key type: %s", keyRec.KeyType)
		return result, nil
	}

	result.Result = "pass"
	result.Reason = "signature verified"
	return result, nil
}

// ComputeHash computes the SHA-256 hash of the given data.
func ComputeHash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// ParseHeaders parses a block of email headers into Header structs.
func ParseHeaders(data []byte) ([]Header, error) {
	normalized := normalizeCRLF(data)
	var headers []Header
	lines := strings.Split(string(normalized), "\r\n")

	var currentName, currentValue strings.Builder
	haveHeader := false

	for _, line := range lines {
		if line == "" {
			break
		}
		if (len(line) > 0 && (line[0] == ' ' || line[0] == '\t')) && haveHeader {
			currentValue.WriteString(" ")
			currentValue.WriteString(strings.TrimSpace(line))
			continue
		}
		if haveHeader {
			headers = append(headers, Header{
				Name:  currentName.String(),
				Value: currentValue.String(),
			})
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		currentName.Reset()
		currentValue.Reset()
		currentName.WriteString(line[:idx])
		currentValue.WriteString(strings.TrimSpace(line[idx+1:]))
		haveHeader = true
	}
	if haveHeader {
		headers = append(headers, Header{
			Name:  currentName.String(),
			Value: currentValue.String(),
		})
	}

	return headers, nil
}

// normalizeCRLF converts all line endings to CRLF.
func normalizeCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	return data
}

// Validate checks a DKIM2 signature for common issues.
func Validate(sig *Signature, key *KeyRecord) []string {
	var issues []string

	if sig == nil {
		return []string{"nil signature"}
	}

	// Check nonce length
	if len(sig.Nonce) > 64 {
		issues = append(issues, "nonce exceeds 64 character limit")
	}

	// Check sequence number
	if sig.SequenceNumber < 1 {
		issues = append(issues, "sequence number must be >= 1")
	}

	// Check key record
	if key != nil {
		if key.IsRevoked() {
			issues = append(issues, "key has been revoked")
		}
	}

	// Check for missing MAIL FROM
	if sig.MailFrom == "" {
		issues = append(issues, "no mf= (MAIL FROM) tag — replay prevention weakened")
	}

	// Check for missing RCPT TO
	if sig.RcptTo == "" {
		issues = append(issues, "no rt= (RCPT TO) tag — replay prevention weakened")
	}

	return issues
}
