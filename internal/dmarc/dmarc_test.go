package dmarc

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.Version != "DMARC1" {
		t.Errorf("Version = %q, want %q", rec.Version, "DMARC1")
	}
	if rec.Policy != PolicyReject {
		t.Errorf("Policy = %q, want %q", rec.Policy, PolicyReject)
	}
	if len(rec.AggregateReportURIs) != 1 {
		t.Fatalf("Expected 1 aggregate URI, got %d", len(rec.AggregateReportURIs))
	}
}

func TestParseRFC9989Tags(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:r@example.com; ruf=mailto:f@example.com; fo=1; sp=reject; psd=y; np=quarantine")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.Policy != PolicyReject {
		t.Errorf("Policy = %q, want %q", rec.Policy, PolicyReject)
	}
	if rec.AlignmentDKIM != "s" {
		t.Errorf("adkim = %q, want %q", rec.AlignmentDKIM, "s")
	}
	if rec.AlignmentSPF != "s" {
		t.Errorf("aspf = %q, want %q", rec.AlignmentSPF, "s")
	}
	if !rec.HasPSD {
		t.Error("Should have psd= tag")
	}
	if rec.PSD != "y" {
		t.Errorf("psd = %q, want %q", rec.PSD, "y")
	}
	if !rec.HasNPDomainPolicy {
		t.Error("Should have np= tag")
	}
	if rec.NPDomainPolicy != PolicyQuarantine {
		t.Errorf("np = %q, want %q", rec.NPDomainPolicy, PolicyQuarantine)
	}
	if rec.SubdomainPolicy != PolicyReject {
		t.Errorf("sp = %q, want %q", rec.SubdomainPolicy, PolicyReject)
	}
}

func TestParseFailureReportOptions(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=none; ruf=mailto:f@example.com; fo=0:1:d:s")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.FailureOptions != "0:1:d:s" {
		t.Errorf("FailureOptions = %q, want %q", rec.FailureOptions, "0:1:d:s")
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{
		"",
		"not dmarc",
		"v=DMARC2; p=none",
		"p=reject",
	}
	for _, input := range tests {
		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) should have failed", input)
		}
	}
}

func TestValidateNoDMARC(t *testing.T) {
	rec, _ := Parse("v=DMARC1; p=none")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "policy is 'none'") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected p=none warning, got: %v", issues)
	}
}

func TestValidateNoReportURIs(t *testing.T) {
	rec, _ := Parse("v=DMARC1; p=reject")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "no rua=") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected rua= warning, got: %v", issues)
	}
}

func TestValidateGood(t *testing.T) {
	rec, _ := Parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com")
	issues := Validate(rec)
	if len(issues) != 0 {
		t.Errorf("Expected no issues, got: %v", issues)
	}
}

func TestValidateSPFAlignment(t *testing.T) {
	rec, _ := Parse("v=DMARC1; p=reject; aspf=s")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "SPF alignment is strict") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected aspf=s strict warning, got: %v", issues)
	}
}

func TestValidateDKIMAlignment(t *testing.T) {
	rec, _ := Parse("v=DMARC1; p=reject; adkim=s")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "DKIM alignment is strict") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected adkim=s strict warning, got: %v", issues)
	}
}

func TestValidateNoFailureReports(t *testing.T) {
	rec, _ := Parse("v=DMARC1; p=reject; rua=mailto:r@example.com")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "no ruf=") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ruf= warning, got: %v", issues)
	}
}

func TestPolicyString(t *testing.T) {
	tests := []struct {
		policy Policy
		want   string
	}{
		{PolicyNone, "none"},
		{PolicyQuarantine, "quarantine"},
		{PolicyReject, "reject"},
		{Policy("invalid"), "invalid"},
	}
	for _, tt := range tests {
		if string(tt.policy) != tt.want {
			t.Errorf("Policy(%q) = %q, want %q", tt.policy, tt.policy, tt.want)
		}
	}
}

func TestParseMultipleURIs(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.com; ruf=mailto:f@example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(rec.AggregateReportURIs) != 2 {
		t.Errorf("Expected 2 aggregate URIs, got %d", len(rec.AggregateReportURIs))
	}
	if len(rec.FailureReportURIs) != 1 {
		t.Errorf("Expected 1 failure URI, got %d", len(rec.FailureReportURIs))
	}
}
