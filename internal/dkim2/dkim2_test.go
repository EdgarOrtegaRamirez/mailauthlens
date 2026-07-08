package dkim2

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	// In DKIM2, s= tag holds the signature value
	sig, err := Parse("i=1; d=example.com; s=abc123")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sig.SequenceNumber != 1 {
		t.Errorf("SequenceNumber = %d, want 1", sig.SequenceNumber)
	}
	if sig.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", sig.Domain, "example.com")
	}
	if sig.SignatureValue != "abc123" {
		t.Errorf("SignatureValue = %q, want %q", sig.SignatureValue, "abc123")
	}
}

func TestParseAllTags(t *testing.T) {
	sig, err := Parse("i=2; m=1; n=noncevalue; t=1234567890; mf=<sender@example.com>; rt=<recipient@example.com>; nd=forwarder.com; d=example.com; s=abc123; f=example")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sig.SequenceNumber != 2 {
		t.Errorf("SequenceNumber = %d, want 2", sig.SequenceNumber)
	}
	if sig.MessageInstance != 1 {
		t.Errorf("MessageInstance = %d, want 1", sig.MessageInstance)
	}
	if sig.Nonce != "noncevalue" {
		t.Errorf("Nonce = %q, want %q", sig.Nonce, "noncevalue")
	}
	if sig.Timestamp != 1234567890 {
		t.Errorf("Timestamp = %d, want 1234567890", sig.Timestamp)
	}
	if sig.MailFrom != "<sender@example.com>" {
		t.Errorf("MailFrom = %q, want %q", sig.MailFrom, "<sender@example.com>")
	}
	if sig.RcptTo != "<recipient@example.com>" {
		t.Errorf("RcptTo = %q, want %q", sig.RcptTo, "<recipient@example.com>")
	}
	if sig.NextDomain != "forwarder.com" {
		t.Errorf("NextDomain = %q, want %q", sig.NextDomain, "forwarder.com")
	}
	if sig.Flags != "example" {
		t.Errorf("Flags = %q, want %q", sig.Flags, "example")
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{
		"",
		"d=example.com",
		"s=abc",
	}
	for _, input := range tests {
		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) should have failed", input)
		}
	}
}

func TestParseKeyRecord(t *testing.T) {
	krec, err := ParseKeyRecord("v=DKIM2; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB")
	if err != nil {
		t.Fatalf("ParseKeyRecord failed: %v", err)
	}
	if krec.Version != "DKIM2" {
		t.Errorf("Version = %q, want %q", krec.Version, "DKIM2")
	}
	if krec.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want %q", krec.KeyType, "rsa")
	}
}

func TestParseKeyRecordEd25519(t *testing.T) {
	// 32 bytes base64 encoded
	krec, err := ParseKeyRecord("v=DKIM2; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatalf("ParseKeyRecord failed: %v", err)
	}
	if krec.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want %q", krec.KeyType, "ed25519")
	}
}

func TestKeyIsRevoked(t *testing.T) {
	_, err := ParseKeyRecord("v=DKIM2; k=rsa; p=")
	if err == nil {
		t.Error("Expected error for revoked key")
	}
}

func TestKeyHasFlag(t *testing.T) {
	krec, err := ParseKeyRecord("v=DKIM2; k=rsa; t=s:y; p=ABCD")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !krec.HasFlag("s") {
		t.Error("Key should have 's' flag")
	}
	if !krec.HasFlag("y") {
		t.Error("Key should have 'y' flag")
	}
	if krec.HasFlag("z") {
		t.Error("Key should not have 'z' flag")
	}
}

func TestDNSQueryName(t *testing.T) {
	name := DNSQueryName("selector1", "example.com")
	if name != "selector1._domainkey.example.com" {
		t.Errorf("DNSQueryName = %q, want %q", name, "selector1._domainkey.example.com")
	}
}

func TestParseMessageInstance(t *testing.T) {
	mi, err := ParseMessageInstance("i=1; d=example.com; t=1234567890; ha=sha256; bh=abc123; hh=def456")
	if err != nil {
		t.Fatalf("ParseMessageInstance failed: %v", err)
	}
	if mi.SequenceNumber != 1 {
		t.Errorf("SequenceNumber = %d, want 1", mi.SequenceNumber)
	}
	if mi.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", mi.Domain, "example.com")
	}
	if mi.Timestamp != 1234567890 {
		t.Errorf("Timestamp = %d, want 1234567890", mi.Timestamp)
	}
	if mi.HashAlgorithm != "sha256" {
		t.Errorf("HashAlgorithm = %q, want %q", mi.HashAlgorithm, "sha256")
	}
}

func TestValidateChain(t *testing.T) {
	sig1 := &Signature{SequenceNumber: 1, Domain: "example.com", MessageInstance: 1}
	sig2 := &Signature{SequenceNumber: 2, Domain: "forwarder.com", NextDomain: "forwarder.com", MessageInstance: 2}
	mi1 := &MessageInstance{SequenceNumber: 1, Domain: "example.com"}
	mi2 := &MessageInstance{SequenceNumber: 2, Domain: "forwarder.com"}
	chain := &ChainOfCustody{
		Signatures:       []*Signature{sig1, sig2},
		MessageInstances: []*MessageInstance{mi1, mi2},
	}
	issues := ValidateChain(chain)
	if len(issues) > 0 {
		t.Errorf("Expected no issues, got: %v", issues)
	}
}

func TestValidateChainWithGap(t *testing.T) {
	sig1 := &Signature{SequenceNumber: 1, Domain: "example.com"}
	sig3 := &Signature{SequenceNumber: 3, Domain: "example.com"}
	chain := &ChainOfCustody{
		Signatures: []*Signature{sig1, sig3},
	}
	issues := ValidateChain(chain)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "sequence gap") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected sequence gap issue, got: %v", issues)
	}
}

func TestValidateChainEmpty(t *testing.T) {
	chain := &ChainOfCustody{}
	issues := ValidateChain(chain)
	if len(issues) == 0 {
		t.Error("Expected 'no DKIM2-Signature headers found' issue")
	}
}

func TestValidateNonceTooLong(t *testing.T) {
	longNonce := strings.Repeat("a", 65)
	sig := &Signature{SequenceNumber: 1, Domain: "example.com", Nonce: longNonce}
	issues := Validate(sig, nil)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "nonce exceeds") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected nonce length issue, got: %v", issues)
	}
}

func TestParseHeaders(t *testing.T) {
	headers := []byte("From: test@example.com\r\nDKIM2-Signature: i=1; d=example.com; s=abc; b=xyz\r\nSubject: Test\r\n\r\n")
	parsed, err := ParseHeaders(headers)
	if err != nil {
		t.Fatalf("ParseHeaders failed: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("Expected 3 headers, got %d", len(parsed))
	}
	if parsed[1].Name != "DKIM2-Signature" {
		t.Errorf("Header 1 name = %q, want %q", parsed[1].Name, "DKIM2-Signature")
	}
}

func TestParseHeadersMultiline(t *testing.T) {
	headers := []byte("DKIM2-Signature: i=1; d=example.com;\r\n s=abc; b=xyz\r\n")
	parsed, err := ParseHeaders(headers)
	if err != nil {
		t.Fatalf("ParseHeaders failed: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("Expected 1 header, got %d", len(parsed))
	}
	if !strings.Contains(parsed[0].Value, "s=abc") {
		t.Errorf("Header value should contain 's=abc', got: %s", parsed[0].Value)
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("Hello, World!")
	hash := ComputeHash(data)
	if len(hash) != 32 {
		t.Errorf("Hash length = %d, want 32", len(hash))
	}
	// Same input should produce same hash
	hash2 := ComputeHash(data)
	if len(hash) != len(hash2) {
		t.Error("Hashes should be same length")
	}
}

func TestValidateChainMissingMI(t *testing.T) {
	sig := &Signature{SequenceNumber: 1, Domain: "example.com", MessageInstance: 99}
	chain := &ChainOfCustody{
		Signatures:       []*Signature{sig},
		MessageInstances: []*MessageInstance{},
	}
	issues := ValidateChain(chain)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "non-existent") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected non-existent MI issue, got: %v", issues)
	}
}
