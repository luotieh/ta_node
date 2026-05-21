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
