package config

import "testing"

func TestLoadConfig(t *testing.T) {
	cfg, err := Load("../../configs/ta_node.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Node.DeviceID != "node-001" {
		t.Fatalf("unexpected device id %q", cfg.Node.DeviceID)
	}
	if cfg.Event.QueueDB == "" {
		t.Fatal("queue db should be set")
	}
}
