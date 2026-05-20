package fingerprint

import (
	"path/filepath"
	"testing"

	"ta_node/internal/parser"
)

func TestLoadThreatJSON(t *testing.T) {
	rules, err := LoadRules(filepath.Join("..", "..", "patterns", "threat.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("expected threat rules")
	}
}

func TestPayloadAndHTTPPartMatch(t *testing.T) {
	engine := New([]PatternRule{
		{ID: "50001", Type: "MINE", Name: "ETH", Protocol: "tcp", Regex: `"method": ?"eth_getWork"`},
		{ID: "h", Type: "SQL", Name: "head", Protocol: "tcp", IsHTTP: 1, Part: "head", Regex: `GET .*union.+select`},
		{ID: "b", Type: "WEB", Name: "body", Protocol: "tcp", IsHTTP: 1, Part: "body", Regex: `secret-body`},
	})
	payload := []byte("GET /?q=union select HTTP/1.1\r\nHost: a.test\r\n\r\nsecret-body")
	pf := parser.PacketFeature{
		PacketTimeUsec: 1,
		Proto:          "tcp",
		HTTPMethod:     "GET",
		Payload:        append([]byte(`{"method":"eth_getWork"}`), payload...),
		HTTPHeader:     []byte("GET /?q=union select HTTP/1.1\r\nHost: a.test"),
		HTTPBody:       []byte("secret-body"),
	}
	hits := engine.Match(pf)
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d: %#v", len(hits), hits)
	}
}
