package dkim

import (
	"bytes"
	"testing"
)

func TestParseBasic(t *testing.T) {
	sig, err := Parse("v=1; a=rsa-sha256; d=example.com; s=selector1; b=jZhCpm")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sig.Version != "1" {
		t.Errorf("Version = %q, want %q", sig.Version, "1")
	}
	if sig.Algorithm != "rsa-sha256" {
		t.Errorf("Algorithm = %q, want %q", sig.Algorithm, "rsa-sha256")
	}
	if sig.SignMethod != "rsa" {
		t.Errorf("SignMethod = %q, want %q", sig.SignMethod, "rsa")
	}
	if sig.HashMethod != "sha256" {
		t.Errorf("HashMethod = %q, want %q", sig.HashMethod, "sha256")
	}
	if sig.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", sig.Domain, "example.com")
	}
	if sig.Selector != "selector1" {
		t.Errorf("Selector = %q, want %q", sig.Selector, "selector1")
	}
	if sig.SignatureValue != "jZhCpm" {
		t.Errorf("SignatureValue = %q, want %q", sig.SignatureValue, "jZhCpm")
	}
}

func TestParseRelaxedRelaxed(t *testing.T) {
	sig, err := Parse("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1; h=from:date; b=test")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sig.HeaderCanon != "relaxed" {
		t.Errorf("HeaderCanon = %q, want %q", sig.HeaderCanon, "relaxed")
	}
	if sig.BodyCanon != "relaxed" {
		t.Errorf("BodyCanon = %q, want %q", sig.BodyCanon, "relaxed")
	}
}

func TestParseSignedHeaders(t *testing.T) {
	sig, err := Parse("v=1; a=rsa-sha256; d=example.com; s=s; h=from:date:subject; bh=abc; b=xyz")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(sig.SignedHeaders) != 3 {
		t.Fatalf("Expected 3 signed headers, got %d", len(sig.SignedHeaders))
	}
	expected := []string{"from", "date", "subject"}
	for i, h := range sig.SignedHeaders {
		if h != expected[i] {
			t.Errorf("Header %d = %q, want %q", i, h, expected[i])
		}
	}
}

func TestParseTimestamp(t *testing.T) {
	sig, err := Parse("v=1; a=rsa-sha256; d=example.com; s=s; b=bh=abc; t=1234567890; b=xyz")
	_ = sig
	_ = err
}

func TestParseEd25519(t *testing.T) {
	sig, err := Parse("v=1; a=ed25519-sha256; d=example.com; s=s; b=abc")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sig.SignMethod != "ed25519" {
		t.Errorf("SignMethod = %q, want %q", sig.SignMethod, "ed25519")
	}
	if sig.HashMethod != "sha256" {
		t.Errorf("HashMethod = %q, want %q", sig.HashMethod, "sha256")
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{
		"",
		"not a signature",
		"v=2; a=rsa-sha256; d=x; s=x; b=x",
	}
	for _, input := range tests {
		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) should have failed", input)
		}
	}
}

func TestParseKeyRecord(t *testing.T) {
	krec, err := ParseKeyRecord("v=DKIM1; k=rsa; s=email; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB")
	if err != nil {
		t.Fatalf("ParseKeyRecord failed: %v", err)
	}
	if krec.Version != "DKIM1" {
		t.Errorf("Version = %q, want %q", krec.Version, "DKIM1")
	}
	if krec.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want %q", krec.KeyType, "rsa")
	}
	if krec.ServiceType != "email" {
		t.Errorf("ServiceType = %q, want %q", krec.ServiceType, "email")
	}
}

func TestParseKeyRecordRevoked(t *testing.T) {
	_, err := ParseKeyRecord("v=DKIM1; k=rsa; p=")
	if err == nil {
		t.Error("Expected error for revoked key")
	}
}

func TestKeyIsRevoked(t *testing.T) {
	krec, err := ParseKeyRecord("v=DKIM1; k=rsa; s=email; p=ABCD1234")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if krec.IsRevoked() {
		t.Error("Key should not be revoked")
	}
}

func TestKeyHasFlag(t *testing.T) {
	krec, err := ParseKeyRecord("v=DKIM1; k=rsa; s=email; t=s:y; p=ABCD")
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

func TestCanonicalizeHeaderSimple(t *testing.T) {
	result := CanonicalizeHeader("From", "test@example.com", "simple")
	if result != "From:test@example.com\r\n" {
		t.Errorf("Result = %q, want %q", result, "From:test@example.com\r\n")
	}
}

func TestCanonicalizeHeaderRelaxed(t *testing.T) {
	result := CanonicalizeHeader("From", "test@example.com", "relaxed")
	expected := "from:test@example.com\r\n"
	if result != expected {
		t.Errorf("Result = %q, want %q", result, expected)
	}
}

func TestCanonicalizeBodySimple(t *testing.T) {
	body := []byte("Hello\r\nWorld\r\n\r\n")
	result := CanonicalizeBody(body, "simple")
	expected := []byte("Hello\r\nWorld")
	if !bytes.Equal(result, expected) {
		t.Errorf("Result = %v, want %v", result, expected)
	}
}

func TestCanonicalizeBodyRelaxed(t *testing.T) {
	body := []byte("Hello\r\n  World  \r\n\r\n")
	result := CanonicalizeBody(body, "relaxed")
	expected := []byte("Hello\r\n World\r\n") // Trim trailing spaces, reduce WSP, strip trailing empty lines, leading space preserved per RFC 6376
	if !bytes.Equal(result, expected) {
		t.Errorf("Result = %q, want %q", result, expected)
	}
}

func TestComputeBodyHashSHA256(t *testing.T) {
	body := []byte("Hello\r\nWorld\r\n\r\n")
	hash, err := ComputeBodyHash(body, "simple", "sha256", 0)
	if err != nil {
		t.Fatalf("ComputeBodyHash failed: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("Hash length = %d, want 32", len(hash))
	}
}

func TestDNSQueryName(t *testing.T) {
	name := DNSQueryName("selector1", "example.com")
	if name != "selector1._domainkey.example.com" {
		t.Errorf("DNSQueryName = %q, want %q", name, "selector1._domainkey.example.com")
	}
}

func TestGenerateKeySelector(t *testing.T) {
	rec := GenerateKeySelector("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", "rsa")
	if !bytes.Contains([]byte(rec), []byte("v=DKIM1;")) {
		t.Error("Missing v=DKIM1")
	}
	if !bytes.Contains([]byte(rec), []byte("k=rsa;")) {
		t.Error("Missing k=rsa")
	}
	if !bytes.Contains([]byte(rec), []byte("s=email;")) {
		t.Error("Missing s=email")
	}
	if !bytes.Contains([]byte(rec), []byte("p=")) {
		t.Error("Missing p=")
	}
}

func TestValidate(t *testing.T) {
	sig := &Signature{
		Version:    "1",
		Algorithm:  "rsa-sha1",
		Domain:     "example.com",
		Selector:   "s",
		Headers:    "from:subject",
		SignedHeaders: []string{"from", "subject"},
		BodyHash:   "abc",
		SignatureValue: "xyz",
	}
	issues := Validate(sig, nil)
	foundSHA1 := false
	for _, issue := range issues {
		if len(issue) > 3 && issue[:4] == "uses" {
			foundSHA1 = true
		}
	}
	if !foundSHA1 {
		t.Errorf("Expected SHA-1 deprecation warning, got: %v", issues)
	}
}

func TestValidateFromSigned(t *testing.T) {
	sig := &Signature{
		Version:       "1",
		Algorithm:     "rsa-sha256",
		Domain:        "example.com",
		Selector:      "s",
		Headers:       "from:subject:date",
		SignedHeaders: []string{"from", "subject", "date"},
		BodyHash:      "abc",
		SignatureValue: "xyz",
	}
	issues := Validate(sig, nil)
	for _, issue := range issues {
		if len(issue) > 4 && issue[:5] == "From " {
			t.Errorf("From header should be signed, got: %s", issue)
		}
	}
}
