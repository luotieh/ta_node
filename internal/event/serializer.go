package event

import "encoding/json"

func Marshal(e ThreatEvent) ([]byte, error) { return json.Marshal(e) }

func Unmarshal(data []byte) (ThreatEvent, error) {
	var e ThreatEvent
	err := json.Unmarshal(data, &e)
	return e, err
}
