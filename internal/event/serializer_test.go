package event

import "testing"

func TestThreatEventJSON(t *testing.T) {
	ev := ThreatEvent{EventID: "e1", DeviceID: "node", EventType: "MINE", RuleID: "50001"}
	data, err := Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.RuleID != "50001" || got.EventID != "e1" {
		t.Fatalf("unexpected event roundtrip: %#v", got)
	}
}
