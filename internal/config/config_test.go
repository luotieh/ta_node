package config

import (
	"testing"
)

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

func TestDefaultIocSync(t *testing.T) {
	c := Default()
	if c.Intel.IocSyncDir != "/data/yt/ioc" {
		t.Errorf("ioc_sync_dir default: %q", c.Intel.IocSyncDir)
	}
	if !c.Intel.EnableIocSync {
		t.Error("enable_ioc_sync default should be true")
	}
	if c.Intel.IocSyncIntervalMin != 60 {
		t.Errorf("ioc_sync_interval_min default: %d", c.Intel.IocSyncIntervalMin)
	}
	if c.Intel.IocSyncRetainDays != 10 {
		t.Errorf("ioc_sync_retain_days default: %d", c.Intel.IocSyncRetainDays)
	}
}
