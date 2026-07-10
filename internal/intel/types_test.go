package intel

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadFileParsesRichFields(t *testing.T) {
	body := `items:
- id: otx-1
  type: domain
  value: evil.example.com
  category: c2
  severity: high
  source: Threat Intel Hub
  recommended_action: block_and_report
  evidence:
    activity: Some Campaign
    threat_labels: [ransomware, phishing]
    source: otx
    cross_check: null
    confidence: high (1 source)
    tlp: white
    misp_event_id: 6a46d120d41fcc87a8a52932
    narrative: null
  enabled: true
`
	var f File
	if err := yaml.Unmarshal([]byte(body), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(f.Items))
	}
	it := f.Items[0]
	if it.RecommendedAction != "block_and_report" {
		t.Errorf("recommended_action: got %q", it.RecommendedAction)
	}
	if it.Evidence == nil {
		t.Fatal("evidence is nil")
	}
	if it.Evidence.Activity != "Some Campaign" || it.Evidence.TLP != "white" {
		t.Errorf("evidence base fields: %+v", it.Evidence)
	}
	if len(it.Evidence.ThreatLabels) != 2 || it.Evidence.MISPEventID != "6a46d120d41fcc87a8a52932" {
		t.Errorf("evidence labels/misp: %+v", it.Evidence)
	}
	if it.Evidence.CrossCheck != "" || it.Evidence.Narrative != "" {
		t.Errorf("null yaml should map to empty string: %+v", it.Evidence)
	}
}
