package intel

import (
	"strings"
	"testing"
)

func TestParseSTIXIndicatorsBundleAndEnvelope(t *testing.T) {
	body := `{
		"type": "bundle",
		"objects": [
			{"type":"indicator","id":"indicator--ip","pattern":"[ipv4-addr:value = '1.2.3.4']","labels":["c2"],"confidence":95,"valid_until":"2026-06-04T00:00:00Z"},
			{"type":"indicator","id":"indicator--domain","pattern":"[domain-name:value = 'evil.example.com']","labels":["malware"],"confidence":70},
			{"type":"indicator","id":"indicator--complex","pattern":"[ipv4-addr:value = '1.2.3.4' OR domain-name:value = 'x']"}
		]
	}`
	result, err := ParseSTIXIndicators(strings.NewReader(body), "hub")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 2 || result.Skipped != 1 {
		t.Fatalf("items=%d skipped=%d", len(result.Items), result.Skipped)
	}
	if result.Items[0].Type != "ip" || result.Items[0].Severity != "critical" || result.Items[0].Category != "c2" || result.Items[0].ExpireAt == 0 {
		t.Fatalf("unexpected ip item: %#v", result.Items[0])
	}

	envelope := `{"objects":[{"type":"indicator","pattern":"[ipv4-addr:value ISSUBSET '45.67.89.0/24']","labels":["scanner"],"confidence":50}]}`
	result, err = ParseSTIXIndicators(strings.NewReader(envelope), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 || result.Items[0].Type != "cidr" || result.Items[0].Source != "Threat Intel Hub" {
		t.Fatalf("unexpected envelope result: %#v", result)
	}
}

func TestParseSTIXPatternSupportedTypes(t *testing.T) {
	cases := map[string]string{
		"[ipv6-addr:value = '2001:db8::1']":          "ip",
		"[url:value = 'http://evil.example.com/a']":  "url",
		"[file:hashes.'SHA-256' = 'abcdef']":         "hash",
		"[file:hashes.MD5 = 'abcdef']":               "hash",
		"[ipv4-addr:value ISSUBSET '45.67.89.0/24']": "cidr",
		"[domain-name:value = 'evil.example.com']":   "domain",
		"[ipv4-addr:value = '1.2.3.4']":              "ip",
	}
	for pattern, wantType := range cases {
		gotType, value, ok := ParseSTIXPattern(pattern)
		if !ok || gotType != wantType || value == "" {
			t.Fatalf("ParseSTIXPattern(%q) = %q %q %v", pattern, gotType, value, ok)
		}
	}
	if _, _, ok := ParseSTIXPattern("[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'x']"); ok {
		t.Fatal("complex pattern should not parse")
	}
}
