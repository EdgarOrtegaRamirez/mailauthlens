// Package dkim implements DKIM (DomainKeys Identified Mail) signature
// parsing, verification, and generation per RFC 6376.
//
// DKIM allows email receivers to verify that a message was signed by
// the claimed domain by querying the domain's DNS for a public key
// and verifying the cryptographic signature.
package dkim

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Signature represents a parsed DKIM-Signature header field.
type Signature struct {
	// Version (v= tag). Should be "1".
	Version string

	// Algorithm (a= tag). E.g., "rsa-sha256", "ed25519-sha256".
	Algorithm string

	// Signature method (extracted from a=).
	SignMethod string // "rsa" or "ed25519"

	// Hash method (extracted from a=).
	HashMethod string // "sha1" or "sha256"

	// Canonicalization (c= tag). E.g., "relaxed/relaxed".
	Canonicalization string

	// Header canonicalization (extracted from c=).
	HeaderCanon string // "simple" or "relaxed"

	// Body canonicalization (extracted from c=).
	BodyCanon string // "simple" or "relaxed"

	// Domain (d= tag). The signing domain.
	Domain string

	// Selector (s= tag). The key selector.
	Selector string

	// Headers (h= tag). Colon-separated list of signed header fields.
	Headers string

	// SignedHeaders is the parsed list from h=.
	SignedHeaders []string

	// BodyHash (bh= tag). Base64-encoded body hash.
	BodyHash string

	// BodyLength (l= tag). Body length count (0 if not present).
	BodyLength int64

	// SignatureValue (b= tag). Base64-encoded signature.
	SignatureValue string

	// Timestamp (t= tag). Signature timestamp (0 if not present).
	Timestamp int64

	// Expiration (x= tag). Signature expiration (0 if not present).
	Expiration int64

	// CopiedHeaders (z= tag). Copied header fields.
	CopiedHeaders string

	// Identity (i= tag). AUID (empty if not present).
	Identity string

	// QueryMethods (q= tag). Query methods (default "dns/txt").
	QueryMethods string

	// Flags (f= tag). Flags (empty if not present).
	Flags string

	// Raw is the raw header value (without folding, but with tag-value list).
	Raw string
}

// Parse parses a DKIM-Signature header value into a Signature struct.
func Parse(headerValue string) (*Signature, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return nil, fmt.Errorf("empty DKIM-Signature header")
	}

	// Unfold (remove CRLF followed by WSP)
	unfolded := unfold(headerValue)

	sig := &Signature{
		Raw:          unfolded,
		BodyLength:   -1,
		Timestamp:    -1,
		Expiration:   -1,
		HeaderCanon:  "simple",
		BodyCanon:    "simple",
		QueryMethods: "dns/txt",
	}

	// Parse tag-value list
	tags, err := parseTagList(unfolded)
	if err != nil {
		return nil, fmt.Errorf("parse tag list: %w", err)
	}

	for _, tag := range tags {
		switch tag.Name {
		case "v":
			sig.Version = tag.Value
		case "a":
			sig.Algorithm = tag.Value
			parts := strings.SplitN(tag.Value, "-", 2)
			if len(parts) == 2 {
				sig.SignMethod = parts[0]
				sig.HashMethod = parts[1]
			}
		case "c":
			sig.Canonicalization = tag.Value
			parts := strings.SplitN(tag.Value, "/", 2)
			if len(parts) >= 1 {
				sig.HeaderCanon = parts[0]
			}
			if len(parts) >= 2 {
				sig.BodyCanon = parts[1]
			} else {
				sig.BodyCanon = "simple"
			}
		case "d":
			sig.Domain = tag.Value
		case "s":
			sig.Selector = tag.Value
		case "h":
			sig.Headers = tag.Value
			sig.SignedHeaders = strings.Split(tag.Value, ":")
			for i, h := range sig.SignedHeaders {
				sig.SignedHeaders[i] = strings.ToLower(strings.TrimSpace(h))
			}
		case "bh":
			sig.BodyHash = tag.Value
		case "b":
			sig.SignatureValue = tag.Value
		case "l":
			var n int64
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				sig.BodyLength = n
			}
		case "t":
			var n int64
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				sig.Timestamp = n
			}
		case "x":
			var n int64
			if _, err := fmt.Sscanf(tag.Value, "%d", &n); err == nil {
				sig.Expiration = n
			}
		case "z":
			sig.CopiedHeaders = tag.Value
		case "i":
			sig.Identity = tag.Value
		case "q":
			sig.QueryMethods = tag.Value
		case "f":
			sig.Flags = tag.Value
		}
	}

	// Validate required tags
	if sig.Version == "" {
		return nil, fmt.Errorf("missing required v= tag")
	}
	if sig.Version != "1" {
		return nil, fmt.Errorf("unsupported DKIM version: %q (must be 1)", sig.Version)
	}
	if sig.Algorithm == "" {
		return nil, fmt.Errorf("missing required a= tag")
	}
	if sig.Domain == "" {
		return nil, fmt.Errorf("missing required d= tag")
	}
	if sig.Selector == "" {
		return nil, fmt.Errorf("missing required s= tag")
	}
	if sig.SignatureValue == "" {
		return nil, fmt.Errorf("missing required b= tag")
	}

	return sig, nil
}

// Tag represents a single tag-value pair in a DKIM tag list.
type Tag struct {
	Name  string
	Value string
}

// parseTagList parses a DKIM tag-value list (tag=value;tag=value;...).
func parseTagList(text string) ([]Tag, error) {
	var tags []Tag
	parts := splitSemicolons(text)
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

// splitSemicolons splits a tag list on ';' characters.
func splitSemicolons(text string) []string {
	return strings.Split(text, ";")
}

// unfold removes CRLF followed by WSP (folding whitespace) from a header value.
func unfold(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n ", " ")
	text = strings.ReplaceAll(text, "\n\t", " ")
	return text
}

// KeyRecord represents a DKIM public key record from DNS.
type KeyRecord struct {
	// Version (v= tag).
	Version string

	// KeyType (k= tag). "rsa" or "ed25519".
	KeyType string

	// HashAlgorithms (h= tag). Accepted hash algorithms.
	HashAlgorithms string

	// KeyData (p= tag). Base64-encoded public key (empty if revoked).
	KeyData string

	// ServiceType (s= tag). Service type (e.g., "email").
	ServiceType string

	// Flags (t= tag). Flags (e.g., "s" for strict, "y" for testing).
	Flags string

	// Notes (n= tag). Human-readable notes.
	Notes string

	// Raw is the original TXT record text.
	Raw string
}

// ParseKeyRecord parses a DKIM DNS TXT record (the key record).
func ParseKeyRecord(text string) (*KeyRecord, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty DKIM key record")
	}

	unfolded := unfold(text)
	rec := &KeyRecord{Raw: unfolded, KeyType: "rsa", ServiceType: "email"}

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
		case "h":
			rec.HashAlgorithms = tag.Value
		case "p":
			rec.KeyData = tag.Value
		case "s":
			rec.ServiceType = tag.Value
		case "t":
			rec.Flags = tag.Value
		case "n":
			rec.Notes = tag.Value
		}
	}

	if rec.KeyData == "" {
		return nil, fmt.Errorf("DKIM key has been revoked (p= tag is empty)")
	}

	return rec, nil
}

// IsRevoked returns true if the key has been revoked (p= tag is empty).
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
// For RSA keys, returns *rsa.PublicKey. For Ed25519, returns ed25519.PublicKey.
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

// parseRSAPublicKey parses a DER-encoded RSA public key (PKCS#1 RSAPublicKey).
func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	if len(der) < 11 {
		return nil, fmt.Errorf("RSA key data too short")
	}

	idx := 0
	if der[idx] != 0x30 { // SEQUENCE tag
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

// parseDERInteger parses a DER INTEGER field and returns a big.Int.
func parseDERInteger(der []byte, idx int) (*big.Int, int, error) {
	if idx >= len(der) {
		return nil, idx, fmt.Errorf("unexpected end of data")
	}
	if der[idx] != 0x02 { // INTEGER tag
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

// Canonicalization functions

// CanonicalizeHeader applies header canonicalization (simple or relaxed).
func CanonicalizeHeader(name, value, method string) string {
	switch method {
	case "relaxed":
		return canonicalizeHeaderRelaxed(name, value)
	default:
		return canonicalizeHeaderSimple(name, value)
	}
}

func canonicalizeHeaderSimple(name, value string) string {
	return name + ":" + value + "\r\n"
}

func canonicalizeHeaderRelaxed(name, value string) string {
	name = strings.ToLower(name)
	value = unfold(value)
	value = strings.TrimSpace(value)
	var b strings.Builder
	inWS := false
	for _, r := range value {
		if r == ' ' || r == '\t' {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
		} else {
			b.WriteRune(r)
			inWS = false
		}
	}
	return name + ":" + b.String() + "\r\n"
}

// CanonicalizeBody applies body canonicalization (simple or relaxed).
func CanonicalizeBody(body []byte, method string) []byte {
	switch method {
	case "relaxed":
		return canonicalizeBodyRelaxed(body)
	default:
		return canonicalizeBodySimple(body)
	}
}

func canonicalizeBodySimple(body []byte) []byte {
	normalized := normalizeCRLF(body)
	lines := strings.Split(string(normalized), "\r\n")

	// Strip trailing whitespace from each line
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " 	")
	}

	// Remove trailing empty lines
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	joined := strings.Join(lines, "\r\n")
	return []byte(joined)
}

func canonicalizeBodyRelaxed(body []byte) []byte {
	normalized := normalizeCRLF(body)
	lines := strings.Split(string(normalized), "\r\n")

	var result []string
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		line = reduceWSP(line)
		result = append(result, line)
	}

	// Remove trailing empty lines
	for len(result) > 0 && result[len(result)-1] == "" {
		result = result[:len(result)-1]
	}

	joined := strings.Join(result, "\r\n")
	if len(joined) > 0 {
		joined += "\r\n"
	}
	return []byte(joined)
}

func reduceWSP(s string) string {
	var b strings.Builder
	inWS := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
		} else {
			b.WriteRune(r)
			inWS = false
		}
	}
	return b.String()
}

// ComputeBodyHash computes the body hash for a DKIM signature.
func ComputeBodyHash(body []byte, canonMethod string, hashMethod string, bodyLength int64) ([]byte, error) {
	canonBody := CanonicalizeBody(body, canonMethod)

	if bodyLength > 0 && bodyLength < int64(len(canonBody)) {
		canonBody = canonBody[:bodyLength]
	}

	switch hashMethod {
	case "sha1":
		sum := sha1.Sum(canonBody)
		return sum[:], nil
	case "sha256":
		sum := sha256.Sum256(canonBody)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash method: %s", hashMethod)
	}
}

// VerifyResult represents the outcome of DKIM verification.
type VerifyResult struct {
	Result    string // "pass", "fail", "temperror", "permerror", "none"
	Reason    string
	Signature *Signature
	KeyRecord *KeyRecord
	Domain    string
	Selector  string
}

// Verify verifies a DKIM signature against an email message.
func Verify(message []byte, resolver DNSResolver) (*VerifyResult, error) {
	headers, body, err := splitMessage(message)
	if err != nil {
		return &VerifyResult{Result: "permerror", Reason: fmt.Sprintf("parse message: %v", err)}, nil
	}

	sigHeaders := findHeaders(headers, "dkim-signature")
	if len(sigHeaders) == 0 {
		return &VerifyResult{Result: "none", Reason: "no DKIM-Signature header found"}, nil
	}

	sig, err := Parse(sigHeaders[0])
	if err != nil {
		return &VerifyResult{Result: "permerror", Reason: fmt.Sprintf("parse signature: %v", err)}, nil
	}

	result := &VerifyResult{
		Signature: sig,
		Domain:    sig.Domain,
		Selector:  sig.Selector,
	}

	// Fetch the public key from DNS
	queryName := DNSQueryName(sig.Selector, sig.Domain)
	txtRecords, err := resolver.LookupTXT(queryName)
	if err != nil {
		result.Result = "temperror"
		result.Reason = fmt.Sprintf("DNS lookup failed for %s: %v", queryName, err)
		return result, nil
	}

	if len(txtRecords) == 0 {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("no DKIM key found at %s", queryName)
		return result, nil
	}

	keyRec, err := ParseKeyRecord(txtRecords[0])
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("parse key record: %v", err)
		return result, nil
	}
	result.KeyRecord = keyRec

	if keyRec.IsRevoked() {
		result.Result = "permerror"
		result.Reason = "DKIM key has been revoked"
		return result, nil
	}

	if keyRec.KeyType != "" && keyRec.KeyType != sig.SignMethod {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("key type mismatch: signature uses %s, key is %s", sig.SignMethod, keyRec.KeyType)
		return result, nil
	}

	// Check hash algorithm
	if keyRec.HashAlgorithms != "" {
		accepted := strings.Split(keyRec.HashAlgorithms, ":")
		found := false
		for _, h := range accepted {
			if strings.TrimSpace(h) == sig.HashMethod {
				found = true
				break
			}
		}
		if !found {
			result.Result = "permerror"
			result.Reason = fmt.Sprintf("hash %s not in accepted list: %s", sig.HashMethod, keyRec.HashAlgorithms)
			return result, nil
		}
	}

	// Compute body hash
	bodyHash, err := ComputeBodyHash(body, sig.BodyCanon, sig.HashMethod, sig.BodyLength)
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("compute body hash: %v", err)
		return result, nil
	}

	// Verify body hash
	expectedHash, err := base64.StdEncoding.DecodeString(sig.BodyHash)
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("decode body hash: %v", err)
		return result, nil
	}

	if !bytes.Equal(bodyHash, expectedHash) {
		result.Result = "fail"
		result.Reason = "body hash mismatch"
		return result, nil
	}

	// Build the signed header data
	pubKey, err := keyRec.PublicKey()
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("parse public key: %v", err)
		return result, nil
	}

	headerData, err := buildSignedHeaderData(headers, sig)
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("build signed header data: %v", err)
		return result, nil
	}

	// Compute header hash
	var hash crypto.Hash
	switch sig.HashMethod {
	case "sha1":
		hash = crypto.SHA1
	case "sha256":
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(headerData)
	headerHash := h.Sum(nil)

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(sig.SignatureValue)
	if err != nil {
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("decode signature: %v", err)
		return result, nil
	}

	// Verify signature
	switch sig.SignMethod {
	case "rsa", "":
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			result.Result = "permerror"
			result.Reason = "expected RSA public key"
			return result, nil
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, hash, headerHash, sigBytes); err != nil {
			result.Result = "fail"
			result.Reason = fmt.Sprintf("RSA signature verification failed: %v", err)
			return result, nil
		}
	case "ed25519":
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			result.Result = "permerror"
			result.Reason = "expected Ed25519 public key"
			return result, nil
		}
		if !ed25519.Verify(edKey, headerHash, sigBytes) {
			result.Result = "fail"
			result.Reason = "Ed25519 signature verification failed"
			return result, nil
		}
	default:
		result.Result = "permerror"
		result.Reason = fmt.Sprintf("unsupported signing method: %s", sig.SignMethod)
		return result, nil
	}

	result.Result = "pass"
	result.Reason = "signature verified successfully"
	return result, nil
}

// buildSignedHeaderData builds the canonicalized header data for signature verification.
func buildSignedHeaderData(headers []Header, sig *Signature) ([]byte, error) {
	var b bytes.Buffer

	for _, hdrName := range sig.SignedHeaders {
		hdrName = strings.ToLower(strings.TrimSpace(hdrName))
		if hdrName == "" {
			continue
		}

		// Find the header (use the last occurrence)
		var found *Header
		for i := len(headers) - 1; i >= 0; i-- {
			if strings.EqualFold(headers[i].Name, hdrName) {
				found = &headers[i]
				break
			}
		}

		if found == nil {
			continue
		}

		value := found.Value
		if strings.EqualFold(found.Name, "dkim-signature") {
			value = emptySignatureValue(value)
		}

		canonical := CanonicalizeHeader(found.Name, value, sig.HeaderCanon)
		b.WriteString(canonical)
	}

	return b.Bytes(), nil
}

// emptySignatureValue replaces the b= tag value with empty string.
func emptySignatureValue(headerValue string) string {
	unfolded := unfold(headerValue)
	result := unfolded
	idx := strings.Index(result, "b=")
	if idx < 0 {
		return result
	}
	end := idx + 2
	for end < len(result) && result[end] != ';' {
		end++
	}
	result = result[:idx+2] + result[end:]
	return result
}

// Header represents an email header.
type Header struct {
	Name  string
	Value string
}

// splitMessage splits an RFC 5322 message into headers and body.
func splitMessage(message []byte) ([]Header, []byte, error) {
	normalized := normalizeCRLF(message)

	sep := []byte("\r\n\r\n")
	idx := bytes.Index(normalized, sep)
	if idx < 0 {
		headers, err := parseHeaders(normalized)
		return headers, nil, err
	}

	headerPart := normalized[:idx]
	bodyPart := normalized[idx+len(sep):]

	headers, err := parseHeaders(headerPart)
	if err != nil {
		return nil, nil, err
	}

	return headers, bodyPart, nil
}

// normalizeCRLF converts all line endings to CRLF.
func normalizeCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	return data
}

// parseHeaders parses a block of email headers.
func parseHeaders(data []byte) ([]Header, error) {
	var headers []Header
	lines := strings.Split(string(data), "\r\n")

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

// findHeaders returns all header values with the given name (case-insensitive).
func findHeaders(headers []Header, name string) []string {
	var result []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			result = append(result, h.Value)
		}
	}
	return result
}

// DNSResolver is the interface for DNS operations used by DKIM.
type DNSResolver interface {
	LookupTXT(domain string) ([]string, error)
}

// GenerateKeySelector generates a DKIM key selector DNS record.
func GenerateKeySelector(publicKeyBase64 string, keyType string) string {
	var b strings.Builder
	b.WriteString("v=DKIM1;")
	if keyType != "" {
		fmt.Fprintf(&b, "k=%s;", keyType)
	}
	b.WriteString("s=email;")
	fmt.Fprintf(&b, "p=%s;", publicKeyBase64)
	return b.String()
}

// Validate checks a DKIM signature for common issues.
func Validate(sig *Signature, key *KeyRecord) []string {
	var issues []string

	if sig == nil {
		return []string{"nil signature"}
	}

	// Check hash method (extract from Algorithm if HashMethod not set)
	hashMethod := sig.HashMethod
	if hashMethod == "" && sig.Algorithm != "" {
		if idx := strings.LastIndex(sig.Algorithm, "-"); idx >= 0 {
			hashMethod = sig.Algorithm[idx+1:]
		}
	}
	if hashMethod == "sha1" {
		issues = append(issues, "uses SHA-1 which is deprecated; use SHA-256")
	}

	if sig.HeaderCanon == "simple" && sig.BodyCanon == "simple" {
		issues = append(issues, "uses simple/simple canonicalization which is fragile to transit modifications; consider relaxed/relaxed")
	}

	if sig.Expiration > 0 && sig.Timestamp > 0 && sig.Expiration < sig.Timestamp {
		issues = append(issues, "expiration time is before timestamp")
	}

	if sig.BodyLength > 0 {
		issues = append(issues, "uses l= (body length) tag which can be exploited to append content")
	}

	if key != nil {
		if key.IsRevoked() {
			issues = append(issues, "key has been revoked")
		}
		if key.HasFlag("y") {
			issues = append(issues, "key is in testing mode (t=y)")
		}
		if !key.HasFlag("s") {
			issues = append(issues, "key does not have strict domain flag (t=s); may be used by subdomains")
		}
	}

	fromSigned := false
	for _, h := range sig.SignedHeaders {
		if h == "from" {
			fromSigned = true
			break
		}
	}
	if !fromSigned {
		issues = append(issues, "From header is not in the signed header list (h=)")
	}

	subjectSigned := false
	for _, h := range sig.SignedHeaders {
		if h == "subject" {
			subjectSigned = true
			break
		}
	}
	if !subjectSigned {
		issues = append(issues, "Subject header is not in the signed header list (h=)")
	}

	return issues
}

// DNSQueryName returns the DNS query name for a DKIM key.
func DNSQueryName(selector, domain string) string {
	return selector + "._domainkey." + domain
}

// ReadMessage reads an RFC 5322 message from a reader.
func ReadMessage(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
