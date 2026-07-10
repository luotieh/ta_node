package config

import (
	"testing"
	"time"
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

func TestDefaultIocWatch(t *testing.T) {
	c := Default()
	if c.Intel.IocWatchDir != "/data/yt/ioc" {
		t.Errorf("ioc_watch_dir default: %q", c.Intel.IocWatchDir)
	}
	if c.Intel.IocWatchIntervalSec != 5 {
		t.Errorf("ioc_watch_interval_sec default: %d", c.Intel.IocWatchIntervalSec)
	}
	if !c.Intel.EnableIocWatch {
		t.Error("enable_ioc_watch default should be true")
	}
	if c.WatchInterval() != 5*time.Second {
		t.Errorf("WatchInterval: %v", c.WatchInterval())
	}
}
