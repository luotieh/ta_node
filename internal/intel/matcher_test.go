package intel

import (
	"path/filepath"
	"testing"

	"ta_node/internal/parser"
)

func TestIntelMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.yaml")
	if err := SaveFile(path, []ThreatIntel{
		{ID: "ip", Type: "ip", Value: "1.2.3.4", Category: "c2", Severity: "high", Enabled: true},
		{ID: "cidr", Type: "cidr", Value: "45.67.89.0/24", Category: "scanner", Severity: "medium", Enabled: true},
		{ID: "domain", Type: "domain", Value: "evil.example.com", Category: "malware", Severity: "high", Enabled: true},
		{ID: "url", Type: "url", Value: "http://bad.example.com/shell.php", Category: "webshell", Severity: "critical", Enabled: true},
		{ID: "expired", Type: "ip", Value: "10.0.0.1", Category: "c2", Severity: "high", Enabled: true, ExpireAt: 1},
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(store)
	pf := parser.PacketFeature{
		SrcIP:      "10.0.0.1",
		DstIP:      "1.2.3.4",
		DNSAnswers: []string{"45.67.89.5"},
		DNSQuery:   "evil.example.com",
		HTTPHost:   "bad.example.com",
		HTTPURL:    "http://bad.example.com/shell.php",
	}
	hits := m.MatchPacket(pf)
	if len(hits) != 4 {
		t.Fatalf("expected 4 hits, got %d: %#v", len(hits), hits)
	}
}

func TestIntelMatcherMatchesCNAMEAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.yaml")
	if err := SaveFile(path, []ThreatIntel{
		{ID: "domain", Type: "domain", Value: "evil.example.com", Category: "malware", Severity: "high", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(store)
	// A benign-looking query whose DNS answer is a CNAME pointing at the IOC.
	pf := parser.PacketFeature{
		SrcIP:      "192.168.1.10",
		DstIP:      "8.8.8.8",
		DNSQuery:   "cdn.example.org",
		DNSAnswers: []string{"evil.example.com"},
	}
	hits := m.MatchPacket(pf)
	if len(hits) != 1 || hits[0].ID != "domain" {
		t.Fatalf("expected CNAME answer to hit domain IOC, got %#v", hits)
	}
}

func TestMatcherMatchesSNI(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(ThreatIntel{ID: "d1", Type: "domain", Value: "evil.example.com", Category: "c2", Severity: "high", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(store)

	if hits := m.MatchPacket(parser.PacketFeature{SNI: "evil.example.com"}); len(hits) != 1 {
		t.Fatalf("SNI exact: want 1 hit, got %d", len(hits))
	}
	if hits := m.MatchPacket(parser.PacketFeature{SNI: "a.b.evil.example.com"}); len(hits) != 1 {
		t.Fatalf("SNI subdomain suffix: want 1 hit, got %d", len(hits))
	}
	if hits := m.MatchPacket(parser.PacketFeature{SNI: "good.example.com"}); len(hits) != 0 {
		t.Fatalf("SNI non-match: want 0 hits, got %d", len(hits))
	}
}
