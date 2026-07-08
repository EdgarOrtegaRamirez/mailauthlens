package spf

import (
	"net"
	"testing"
)

// mockResolver implements DNSResolver for testing.
type mockResolver struct {
	ipRecords  map[string][]net.IP
	mxRecords  map[string][]*net.MX
	ptrRecords map[string][]string
	spfRecords map[string]*Record
	txtRecords map[string][]string
}

func newMockResolver() *mockResolver {
	return &mockResolver{
		ipRecords:  make(map[string][]net.IP),
		mxRecords:  make(map[string][]*net.MX),
		ptrRecords: make(map[string][]string),
		spfRecords: make(map[string]*Record),
		txtRecords: make(map[string][]string),
	}
}

func (m *mockResolver) LookupIP(domain string) ([]net.IP, error) {
	if ips, ok := m.ipRecords[domain]; ok {
		return ips, nil
	}
	return nil, nil
}

func (m *mockResolver) LookupMX(domain string) ([]*net.MX, error) {
	if mxs, ok := m.mxRecords[domain]; ok {
		return mxs, nil
	}
	return nil, nil
}

func (m *mockResolver) LookupPTR(ip string) ([]string, error) {
	if names, ok := m.ptrRecords[ip]; ok {
		return names, nil
	}
	return nil, nil
}

func (m *mockResolver) LookupSPF(domain string) (*Record, error) {
	if rec, ok := m.spfRecords[domain]; ok {
		return rec, nil
	}
	return nil, nil
}

func (m *mockResolver) LookupTXT(domain string) ([]string, error) {
	if recs, ok := m.txtRecords[domain]; ok {
		return recs, nil
	}
	return nil, nil
}

func TestParseBasic(t *testing.T) {
	rec, err := Parse("v=spf1 ip4:192.168.1.0/24 -all")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.Version != "spf1" {
		t.Errorf("Version = %q, want %q", rec.Version, "spf1")
	}
	if len(rec.Mechanisms) != 2 {
		t.Fatalf("Expected 2 mechanisms, got %d", len(rec.Mechanisms))
	}
	if rec.Mechanisms[0].Type != "ip4" {
		t.Errorf("First mechanism type = %q, want %q", rec.Mechanisms[0].Type, "ip4")
	}
	if rec.Mechanisms[0].Value != "192.168.1.0" {
		t.Errorf("First mechanism value = %q, want %q", rec.Mechanisms[0].Value, "192.168.1.0")
	}
	if rec.Mechanisms[0].PrefixLen != 24 {
		t.Errorf("First mechanism prefix = %d, want 24", rec.Mechanisms[0].PrefixLen)
	}
	if rec.Mechanisms[1].Type != "all" {
		t.Errorf("Second mechanism type = %q, want %q", rec.Mechanisms[1].Type, "all")
	}
	if rec.Mechanisms[1].Qualifier != '-' {
		t.Errorf("Second mechanism qualifier = %q, want '-'", rec.Mechanisms[1].Qualifier)
	}
}

func TestParseQualifiers(t *testing.T) {
	tests := []struct {
		input    string
		qual     rune
	}{
		{"v=spf1 +all", '+'},
		{"v=spf1 -all", '-'},
		{"v=spf1 ~all", '~'},
		{"v=spf1 ?all", '?'},
		{"v=spf1 all", '+'},
	}

	for _, tt := range tests {
		rec, err := Parse(tt.input)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", tt.input, err)
		}
		if rec.Mechanisms[0].Qualifier != tt.qual {
			t.Errorf("Parse(%q): qualifier = %q, want %q", tt.input, rec.Mechanisms[0].Qualifier, tt.qual)
		}
	}
}

func TestParseMechanisms(t *testing.T) {
	rec, err := Parse("v=spf1 include:example.com a mx a:mail.example.com mx:mail.example.com ip4:10.0.0.1 ip6:fe80::1 exists:check.example.com ptr -all")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(rec.Mechanisms) != 10 {
		t.Fatalf("Expected 10 mechanisms, got %d", len(rec.Mechanisms))
	}

	expected := []string{"include", "a", "mx", "a", "mx", "ip4", "ip6", "exists", "ptr", "all"}
	for i, m := range rec.Mechanisms {
		if m.Type != expected[i] {
			t.Errorf("Mechanism %d type = %q, want %q", i, m.Type, expected[i])
		}
	}
}

func TestParseRedirect(t *testing.T) {
	rec, err := Parse("v=spf1 ip4:192.168.1.1 redirect=example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.Redirect != "example.com" {
		t.Errorf("Redirect = %q, want %q", rec.Redirect, "example.com")
	}
}

func TestParseExp(t *testing.T) {
	rec, err := Parse("v=spf1 -all exp=explain.example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.Explanation != "explain.example.com" {
		t.Errorf("Explanation = %q, want %q", rec.Explanation, "explain.example.com")
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{
		"",
		"not spf",
		"v=spf1 invalidmechanism",
	}
	for _, input := range tests {
		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) should have failed", input)
		}
	}
}

func TestValidateAllNotLast(t *testing.T) {
	rec, _ := Parse("v=spf1 -all ip4:192.168.1.1")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if len(issue) > 10 && issue[:10] == "'all' mech" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected 'all' not last issue, got: %v", issues)
	}
}

func TestValidatePlusAll(t *testing.T) {
	rec, _ := Parse("v=spf1 +all")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if issue != "" && len(issue) > 20 && issue[:20] == "'all' mechanism uses" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected +all warning, got: %v", issues)
	}
}

func TestValidateNoAll(t *testing.T) {
	rec, _ := Parse("v=spf1 ip4:192.168.1.1")
	issues := Validate(rec)
	if len(issues) == 0 {
		t.Error("Expected issues for record without 'all'")
	}
}

func TestValidatePtrDeprecated(t *testing.T) {
	rec, _ := Parse("v=spf1 ptr -all")
	issues := Validate(rec)
	found := false
	for _, issue := range issues {
		if issue != "" && len(issue) > 3 && issue[:4] == "'ptr" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ptr deprecated warning, got: %v", issues)
	}
}

func TestValidateGood(t *testing.T) {
	rec, _ := Parse("v=spf1 ip4:192.168.1.0/24 -all")
	issues := Validate(rec)
	if len(issues) != 0 {
		t.Errorf("Expected no issues, got: %v", issues)
	}
}

func TestEvaluateIP4Match(t *testing.T) {
	rec, _ := Parse("v=spf1 ip4:192.168.1.0/24 -all")
	resolver := newMockResolver()

	result, _, err := Evaluate(rec, net.ParseIP("192.168.1.100"), "example.com", resolver)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result != ResultPass {
		t.Errorf("Result = %q, want %q", result, ResultPass)
	}
}

func TestEvaluateIP4NoMatch(t *testing.T) {
	rec, _ := Parse("v=spf1 ip4:192.168.1.0/24 -all")
	resolver := newMockResolver()

	result, _, err := Evaluate(rec, net.ParseIP("10.0.0.1"), "example.com", resolver)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result != ResultFail {
		t.Errorf("Result = %q, want %q", result, ResultFail)
	}
}

func TestEvaluateAll(t *testing.T) {
	rec, _ := Parse("v=spf1 -all")
	resolver := newMockResolver()

	result, _, _ := Evaluate(rec, net.ParseIP("192.168.1.1"), "example.com", resolver)
	if result != ResultFail {
		t.Errorf("Result = %q, want %q", result, ResultFail)
	}
}

func TestEvaluateAMechanism(t *testing.T) {
	rec, _ := Parse("v=spf1 a -all")
	resolver := newMockResolver()
	resolver.ipRecords["example.com"] = []net.IP{net.ParseIP("192.168.1.1")}

	result, _, _ := Evaluate(rec, net.ParseIP("192.168.1.1"), "example.com", resolver)
	if result != ResultPass {
		t.Errorf("Result = %q, want %q", result, ResultPass)
	}
}

func TestEvaluateMXMechanism(t *testing.T) {
	rec, _ := Parse("v=spf1 mx -all")
	resolver := newMockResolver()
	resolver.mxRecords["example.com"] = []*net.MX{{Host: "mail.example.com", Pref: 10}}
	resolver.ipRecords["mail.example.com"] = []net.IP{net.ParseIP("192.168.1.1")}

	result, _, _ := Evaluate(rec, net.ParseIP("192.168.1.1"), "example.com", resolver)
	if result != ResultPass {
		t.Errorf("Result = %q, want %q", result, ResultPass)
	}
}

func TestEvaluateInclude(t *testing.T) {
	mainRec, _ := Parse("v=spf1 include:other.com -all")
	subRec, _ := Parse("v=spf1 ip4:10.0.0.1 -all")
	resolver := newMockResolver()
	resolver.spfRecords["other.com"] = subRec

	result, _, _ := Evaluate(mainRec, net.ParseIP("10.0.0.1"), "example.com", resolver)
	if result != ResultPass {
		t.Errorf("Result = %q, want %q", result, ResultPass)
	}
}

func TestEvaluateExists(t *testing.T) {
	rec, _ := Parse("v=spf1 exists:check.example.com -all")
	resolver := newMockResolver()
	resolver.ipRecords["check.example.com"] = []net.IP{net.ParseIP("127.0.0.1")}

	result, _, _ := Evaluate(rec, net.ParseIP("192.168.1.1"), "example.com", resolver)
	if result != ResultPass {
		t.Errorf("Result = %q, want %q", result, ResultPass)
	}
}

func TestEvaluateSoftFail(t *testing.T) {
	rec, _ := Parse("v=spf1 ~all")
	resolver := newMockResolver()

	result, _, _ := Evaluate(rec, net.ParseIP("192.168.1.1"), "example.com", resolver)
	if result != ResultSoftFail {
		t.Errorf("Result = %q, want %q", result, ResultSoftFail)
	}
}

func TestEvaluateNeutral(t *testing.T) {
	rec, _ := Parse("v=spf1 ?all")
	resolver := newMockResolver()

	result, _, _ := Evaluate(rec, net.ParseIP("192.168.1.1"), "example.com", resolver)
	if result != ResultNeutral {
		t.Errorf("Result = %q, want %q", result, ResultNeutral)
	}
}

func TestMechanismString(t *testing.T) {
	m := Mechanism{Qualifier: '-', Type: "ip4", Value: "192.168.1.0", PrefixLen: 24}
	s := m.String()
	expected := "-ip4:192.168.1.0/24"
	if s != expected {
		t.Errorf("String() = %q, want %q", s, expected)
	}
}

func TestParseCIDRDual(t *testing.T) {
	rec, err := Parse("v=spf1 a/24//64 -all")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rec.Mechanisms[0].PrefixLen != 24 {
		t.Errorf("IPv4 prefix = %d, want 24", rec.Mechanisms[0].PrefixLen)
	}
	if rec.Mechanisms[0].PrefixLen6 != 64 {
		t.Errorf("IPv6 prefix = %d, want 64", rec.Mechanisms[0].PrefixLen6)
	}
}
